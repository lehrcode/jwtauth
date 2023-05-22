package main

import (
	"flag"
	"fmt"
	"github.com/lehrcode/jwtauth"
	"log"
	"net/http"
)

func main() {
	addr := flag.String("addr", "", "address to serve on")
	port := flag.Int("port", 8000, "port to serve on")
	directory := flag.String("dir", ".", "the directory of static file to serve")
	jwksURI := flag.String("jwks", "jwks.json", "json web key set uri (http or local file")
	flag.Parse()

	jwks, err := jwtauth.KeySetFromURI(*jwksURI)
	if err != nil {
		log.Fatal(err)
	}
	requireToken := jwtauth.RequireToken(jwtauth.RequireTokenOptions{KeySet: jwks})

	http.Handle("/", requireToken(http.FileServer(http.Dir(*directory))))
	http.Handle("/whoami", requireToken(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "User ID:", r.Context().Value("user_id"))
	})))

	log.Printf("Serving %s on %s:%d\n", *directory, *addr, *port)
	if err := http.ListenAndServe(fmt.Sprintf("%s:%d", *addr, *port), nil); err != nil {
		log.Fatal(err)
	}
}
