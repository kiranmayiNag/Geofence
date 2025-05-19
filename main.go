package main

import (
    "crypto/tls"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "strings"
    "time"
    "os"

    "github.com/golang-jwt/jwt/v5"
    "github.com/gorilla/mux"
)

// Secret key for JWT signing and validation
var jwtSecret = []byte("your-secret-key")

// Struct for incoming location data
type LocationUpdate struct {
    DeviceID string  `json:"device_id"`
    Lat      float64 `json:"latitude"`
    Lng      float64 `json:"longitude"`
    Time     string  `json:"timestamp"`
}

// Middleware to check JWT token
func jwtMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        authHeader := r.Header.Get("Authorization")
        if !strings.HasPrefix(authHeader, "Bearer ") {
            http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
            return
        }

        tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
        token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
            // Validate the algorithm
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("unexpected signing method")
            }
            return jwtSecret, nil
        })

        if err != nil || !token.Valid {
            http.Error(w, "Invalid token", http.StatusUnauthorized)
            return
        }

        next.ServeHTTP(w, r)
    })
}

// Handler for location update
func locationUpdateHandler(w http.ResponseWriter, r *http.Request) {
    var loc LocationUpdate
    if err := json.NewDecoder(r.Body).Decode(&loc); err != nil {
        http.Error(w, "Invalid JSON", http.StatusBadRequest)
        return
    }

    log.Printf("Received location from %s: (%f, %f) at %s\n", loc.DeviceID, loc.Lat, loc.Lng, loc.Time)
    w.WriteHeader(http.StatusOK)
    w.Write([]byte(`{"status":"received"}`))
}

// Generate a sample JWT (for testing)
func generateJWT() string {
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
        "sub": "device123",
        "exp": time.Now().Add(time.Hour * 24).Unix(),
    })

    tokenString, err := token.SignedString(jwtSecret)
    if err != nil {
        log.Fatal(err)
    }
    return tokenString
}

func main() {
    r := mux.NewRouter()
    r.Handle("/api/location-update", jwtMiddleware(http.HandlerFunc(locationUpdateHandler))).Methods("POST")

    port := os.Getenv("PORT")
    if port == "" {
        port = "8080" // fallback for local
    }

    // Print sample token
    fmt.Println("Sample JWT:", generateJWT())
    fmt.Println("Listening on port", port)

    log.Fatal(http.ListenAndServe(":"+port, r))
}
