package handlers

import (
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"

	"jwks-server/internal/keys"
)

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func JWKSHandler(manager *keys.Manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		key := manager.GetValidKey()
		pub := key.PrivateKey.PublicKey

		jwks := JWKS{
			Keys: []JWK{
				{
					Kid: key.Kid,
					Kty: "RSA",
					Alg: "RS256",
					Use: "sig",
					N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
					E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwks)
	}
}
