package jwtauth

import (
	"context"
	"fmt"
	"github.com/go-jose/go-jose/v3"
	"net/http"
	"strings"
)

type RequireTokenOptions struct {
	KeySet    *jose.JSONWebKeySet
	ErrorFunc func(http.ResponseWriter, string, int)
}

// bearerToken extracts token value from Authorization header
func bearerToken(r *http.Request) string {
	var fields = strings.Fields(r.Header.Get("Authorization"))
	if len(fields) == 2 && strings.EqualFold("Bearer", fields[0]) {
		return fields[1]
	}
	return ""
}

func RequireToken(options RequireTokenOptions) func(http.Handler) http.Handler {
	if options.ErrorFunc == nil {
		options.ErrorFunc = http.Error
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var rawToken = bearerToken(r)
			if rawToken == "" {
				w.Header().Set("WWW-Authenticate", "Bearer")
				options.ErrorFunc(w, "Authentication Required", http.StatusUnauthorized)
				return
			}

			var userID, err = validateToken(rawToken, options.KeySet)
			if err != nil {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf("Bearer error=\"invalid_token\", error_description=\"%s\"", err.Error()))
				options.ErrorFunc(w, err.Error(), http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), "user_id", userID)))
		})
	}
}
