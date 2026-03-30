package handlers

import (
	"net/http"
	"time"

	"jwks-server/internal/keys"

	"github.com/golang-jwt/jwt/v5"
)

func AuthHandler(manager *keys.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		expired := r.URL.Query().Get("expired")

		var key *keys.Key
		if expired == "true" {
			key = manager.GetExpiredKey()
		} else {
			key = manager.GetValidKey()
		}

		claims := jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(key.ExpiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "jwks-server",
			Subject:   "fake-user",
		}

		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = key.Kid

		signed, err := token.SignedString(key.PrivateKey)
		if err != nil {
			http.Error(w, "could not sign token", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"token":"` + signed + `"}`))
	}
}