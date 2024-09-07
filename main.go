/*
This Go server implements basic authentication, CORS validation, IP banning, and graceful shutdown. It tracks failed login attempts, bans IPs after multiple failed attempts, and provides a health check endpoint. The server listens on a configurable port and supports graceful shutdown upon receiving termination signals. Periodic cleanup of old banned IPs and failed login attempts is also handled in the background.
*/

package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var (
	allowedOrigins       []string
	username             string
	password             string
	maxFailedAttempts    int
	banDuration          time.Duration
	failedLoginRetention = 1 * time.Hour
	failedLoginAttempts  sync.Map
	bannedIPs            sync.Map
	mu                   sync.Mutex
)

func init() {
	allowedOriginsEnv := os.Getenv("ALLOWED_ORIGINS")
	if allowedOriginsEnv != "" {
		allowedOrigins = strings.Split(allowedOriginsEnv, ",")
	} else {
		allowedOrigins = []string{"http://localhost:3000"}
	}

	username = os.Getenv("USERNAME")
	if username == "" {
		username = "admin"
		log.Printf("Warning: Using default username 'admin'")
	}
	password = os.Getenv("PASSWORD")
	if password == "" {
		password = "password"
		log.Printf("Warning: Using default password 'password'")
	}

	maxFailedAttemptsEnv := os.Getenv("MAX_FAILED_ATTEMPTS")
	maxFailedAttempts = 3
	if maxFailedAttemptsEnv != "" {
		if val, err := strconv.Atoi(maxFailedAttemptsEnv); err == nil {
			maxFailedAttempts = val
		} else {
			log.Printf("Invalid MAX_FAILED_ATTEMPTS value: %v, falling back to default (3)", err)
		}
	}

	banDurationEnv := os.Getenv("BAN_DURATION_HOURS")
	banDuration = time.Hour
	if banDurationEnv != "" {
		if banHours, err := strconv.Atoi(banDurationEnv); err == nil {
			banDuration = time.Duration(banHours) * time.Hour
		} else {
			log.Printf("Invalid BAN_DURATION_HOURS value: %v, falling back to 1 hour", err)
		}
	}
}

func isIPBanned(ip string) bool {
	if banTimeVal, exists := bannedIPs.Load(ip); exists {
		banTime := banTimeVal.(time.Time)
		if time.Now().Before(banTime) {
			return true
		}
		bannedIPs.Delete(ip)
	}
	return false
}

func trackFailedAttempt(ip string) {
	now := time.Now()
	if attemptsVal, exists := failedLoginAttempts.Load(ip); exists {
		attempts := attemptsVal.(int)
		attempts++
		if attempts >= maxFailedAttempts {
			bannedIPs.Store(ip, now.Add(banDuration))
			failedLoginAttempts.Delete(ip)
			log.Printf("IP %s has been banned for %v", ip, banDuration)
		} else {
			failedLoginAttempts.Store(ip, attempts)
		}
	} else {
		failedLoginAttempts.Store(ip, 1)
	}
}

func resetFailedAttempts(ip string) {
	failedLoginAttempts.Delete(ip)
}

func validateOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	for _, allowed := range allowedOrigins {
		if allowed == origin {
			return true
		}
	}
	return false
}

func getClientIP(r *http.Request) string {
	xff := r.Header.Get("X-Forwarded-For")
	if xff != "" {
		ips := strings.Split(xff, ",")
		clientIP := strings.TrimSpace(ips[0])
		if parsedIP := net.ParseIP(clientIP); parsedIP != nil {
			return clientIP
		}
	}

	remoteIP := strings.Split(r.RemoteAddr, ":")[0]
	if parsedIP := net.ParseIP(remoteIP); parsedIP != nil {
		return remoteIP
	}

	return ""
}

func basicAuth(r *http.Request) (bool, string) {
	ip := getClientIP(r)

	if isIPBanned(ip) {
		return false, "Your IP is banned. Try again later."
	}

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return false, "Authorization required"
	}

	encodedCredentials := strings.SplitN(authHeader, " ", 2)[1]
	decoded, err := base64.StdEncoding.DecodeString(encodedCredentials)
	if err != nil {
		return false, "Invalid base64 encoding"
	}
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return false, "Invalid credentials format"
	}

	if parts[0] == username && parts[1] == password {
		resetFailedAttempts(ip)
		return true, ""
	}

	trackFailedAttempt(ip)
	return false, "Invalid credentials"
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, "Gateway is up and running")
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	if !validateOrigin(r) {
		http.Error(w, "Origin not allowed", http.StatusForbidden)
		return
	}

	auth, msg := basicAuth(r)
	if !auth {
		w.Header().Set("WWW-Authenticate", `Basic realm="Restricted Area"`)
		http.Error(w, msg, http.StatusUnauthorized)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintln(w, "Authenticated")
}

func cleanupBannedIPs() {
	for {
		time.Sleep(1 * time.Minute)
		bannedIPs.Range(func(key, value interface{}) bool {
			banTime := value.(time.Time)
			if time.Now().After(banTime) {
				bannedIPs.Delete(key)
				log.Printf("IP %s ban lifted", key)
			}
			return true
		})
	}
}

func cleanupFailedLoginAttempts() {
	for {
		time.Sleep(1 * time.Minute)
		failedLoginAttempts.Range(func(key, value interface{}) bool {
			if attempts := value.(int); attempts > 0 {
				failedLoginAttempts.Delete(key)
				log.Printf("Removed stale login attempts for IP %s", key)
			}
			return true
		})
	}
}


func main() {
	go cleanupBannedIPs()
	go cleanupFailedLoginAttempts()

	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/verify", verifyHandler)

	port := 3000
	if p := os.Getenv("PORT"); p != "" {
		if parsedPort, err := strconv.Atoi(p); err == nil {
			port = parsedPort
		} else {
			log.Printf("Invalid PORT value: %v, using default 3000", err)
		}
	}

	srv := &http.Server{
		Addr:         fmt.Sprintf(":%d", port),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	go func() {
		log.Printf("Server starting on port %d", port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %s", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop
	log.Println("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server shutdown failed: %s", err)
	}

	log.Println("Server exited properly")
}
