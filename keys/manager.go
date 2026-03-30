package keys

import (
	"crypto/rand"
	"crypto/rsa"
	"time"

	"github.com/google/uuid"
)

type Key struct {
	PrivateKey *rsa.PrivateKey
	Kid        string
	ExpiresAt  time.Time
}

type Manager struct {
	Keys []*Key
}

func NewManager() (*Manager, error) {
	validKey, err := generateKey(time.Now().Add(1 * time.Hour))
	if err != nil {
		return nil, err
	}

	expiredKey, err := generateKey(time.Now().Add(-1 * time.Hour))
	if err != nil {
		return nil, err
	}

	return &Manager{
		Keys: []*Key{validKey, expiredKey},
	}, nil
}

func generateKey(expiry time.Time) (*Key, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return &Key{
		PrivateKey: priv,
		Kid:        uuid.New().String(),
		ExpiresAt:  expiry,
	}, nil
}

func (m *Manager) GetValidKey() *Key {
	for _, k := range m.Keys {
		if k.ExpiresAt.After(time.Now()) {
			return k
		}
	}
	return nil
}

func (m *Manager) GetExpiredKey() *Key {
	for _, k := range m.Keys {
		if k.ExpiresAt.Before(time.Now()) {
			return k
		}
	}
	return nil
}
