package jwtauth

import (
	"errors"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"time"
)

var ErrEmptyKeySet = errors.New("key set is empty")

func validateToken(rawToken string, jwks *jose.JSONWebKeySet) (string, error) {
	var token, err = jwt.ParseSigned(rawToken)
	if err != nil {
		return "", err
	}
	if jwks == nil || len(jwks.Keys) == 0 {
		return "", ErrEmptyKeySet
	}
	var publicKey = jwks.Keys[0].Public().Key
	// find public key
	if len(token.Headers) > 0 && token.Headers[0].KeyID != "" {
		if keys := jwks.Key(token.Headers[0].KeyID); len(keys) > 0 {
			publicKey = keys[0].Public().Key
		}
	}
	var claims = jwt.Claims{}
	if err := token.Claims(publicKey, &claims); err != nil {
		return "", err
	}
	err = claims.ValidateWithLeeway(jwt.Expected{
		Time: time.Now(),
	}, 0)
	if err != nil {
		return "", err
	} else {
		return claims.Subject, nil
	}
}
