package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"jwks-server/internal/keys"
)

func setupManager(t *testing.T) *keys.Manager {
	manager, err := keys.NewManager()
	if err != nil {
		t.Fatalf("Failed to create key manager: %v", err)
	}
	return manager
}
func TestJWKSHandler(t *testing.T) {
	manager := setupManager(t)

	req := httptest.NewRequest("GET", "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()

	handler := JWKSHandler(manager)
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}
func TestAuthHandlerValid(t *testing.T) {
	manager := setupManager(t)

	req := httptest.NewRequest("POST", "/auth", nil)
	w := httptest.NewRecorder()

	handler := AuthHandler(manager)
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}
func TestAuthHandlerExpired(t *testing.T) {
	manager := setupManager(t)

	req := httptest.NewRequest("POST", "/auth?expired=true", nil)
	w := httptest.NewRecorder()

	handler := AuthHandler(manager)
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected 200, got %d", w.Code)
	}
}
func TestAuthWrongMethod(t *testing.T) {
	manager := setupManager(t)

	req := httptest.NewRequest("GET", "/auth", nil)
	w := httptest.NewRecorder()

	handler := AuthHandler(manager)
	handler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected 405, got %d", w.Code)
	}
}
