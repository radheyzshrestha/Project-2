package main

import (
	"fmt"
	"log"
	"net/http"

	"jwks-server/internal/handlers"
	"jwks-server/internal/keys"
)

func main() {
	manager, err := keys.NewManager()
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/.well-known/jwks.json", handlers.JWKSHandler(manager))
	http.HandleFunc("/auth", handlers.AuthHandler(manager))

	
    fmt.Println("Server running on 127.0.0.1:8080")
    http.ListenAndServe("127.0.0.1:8080", nil)

}
