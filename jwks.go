package jwtauth

import (
	"encoding/json"
	"fmt"
	"github.com/go-jose/go-jose/v3"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
)

func PublicKeysFromJWKS(jwksURI string) (map[string]any, error) {
	var jwksBytes []byte

	if strings.HasPrefix(jwksURI, "http://") || strings.HasPrefix(jwksURI, "https://") {
		log.Printf("GET %s", jwksURI)
		if resp, err := http.Get(jwksURI); err == nil && resp.StatusCode == http.StatusOK {
			jwksBytes, err = io.ReadAll(resp.Body)
			if err != nil {
				return nil, err
			}
		} else {
			if err != nil {
				return nil, err
			} else {
				return nil, fmt.Errorf("%s", resp.Status)
			}
		}
	} else {
		var err error
		jwksBytes, err = os.ReadFile(jwksURI)
		if err != nil {
			return nil, err
		}
	}

	var rawJwks map[string][]map[string]string

	if err := json.Unmarshal(jwksBytes, &rawJwks); err != nil {
		return nil, err
	}

	var publicKeys = make(map[string]any, len(rawJwks["keys"]))

	for _, rawJwk := range rawJwks["keys"] {
		var jwkBytes, _ = json.Marshal(rawJwk)
		var jwk = &jose.JSONWebKey{}
		if err := jwk.UnmarshalJSON(jwkBytes); err != nil {
			panic(err)
		}
		publicKeys[jwk.KeyID] = jwk.Key
	}

	return publicKeys, nil
}
