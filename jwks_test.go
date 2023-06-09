package jwtauth

import (
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

const ecdsaKeySet = `{"keys":[{"use":"sig","kty":"EC","kid":"key1","crv":"P-384","x":"bGwGcCYzHp7Iqip0-5SFEu7jOJO9L1hAXue2JKNX0KaX51VgLXBhRIQVsLqsDyrm","y":"rg07D7EniQkDuQenb_Dw09IZwB3DdBCZVtJZ44s4ik3xwGjG4o8vfBRnv4rbeqv9"}]}`

func TestPublicKeysFromJWKS(t *testing.T) {
	// Start a local HTTP server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/jwks.json" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(ecdsaKeySet))
	}))
	// Close the server when test finishes
	defer server.Close()

	t.Run("http_ok", func(t *testing.T) {
		keySet, err := KeySetFromURI(server.URL + "/jwks.json")
		if err != nil {
			t.Errorf("KeySetFromURI() error = %v", err)
			return
		}
		if keySet == nil || len(keySet.Key("key1")) != 1 {
			t.Errorf("KeySetFromURI() keySet = %v, but should be map with 1 entry", keySet)
		}
	})

	t.Run("http_failure", func(t *testing.T) {
		_, err := KeySetFromURI(server.URL + "/wrong_path")
		if err == nil {
			t.Errorf("KeySetFromURI() error = nil")
		} else {
			log.Print(err)
		}
	})

	var jwksFilename string
	if f, err := os.CreateTemp("", "jwks-*.json"); err == nil {
		if _, err := f.WriteString(ecdsaKeySet); err != nil {
			t.Error(err)
			return
		}
		jwksFilename = f.Name()
		f.Close()
		defer os.Remove(jwksFilename)
	} else {
		t.Error(err)
		return
	}

	t.Run("file_ok", func(t *testing.T) {
		keySet, err := KeySetFromURI(jwksFilename)
		if err != nil {
			t.Errorf("KeySetFromURI() error = %v", err)
			return
		}
		if keySet == nil || len(keySet.Key("key1")) != 1 {
			t.Errorf("KeySetFromURI() keySet = %v, but should be map with 1 entry", keySet)
		}
	})
	t.Run("file_not_found", func(t *testing.T) {
		_, err := KeySetFromURI("unknown_jwks.json")
		if err == nil {
			t.Errorf("KeySetFromURI() error = nil")
		} else {
			log.Print(err)
		}
	})
}
