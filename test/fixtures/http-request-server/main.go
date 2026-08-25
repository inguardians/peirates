package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

func validateRequest(mode string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "expected POST", http.StatusBadRequest)
			return
		}
		if r.Header.Get("X-Peirates-Mode") != mode {
			http.Error(w, "unexpected X-Peirates-Mode header", http.StatusBadRequest)
			return
		}
		if r.Header.Get("X-Peirates-Trace") != mode+"-trace" {
			http.Error(w, "unexpected X-Peirates-Trace header", http.StatusBadRequest)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			http.Error(w, "unexpected Content-Type header", http.StatusBadRequest)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "could not parse request form", http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("alpha") != mode+"-one" || r.PostForm.Get("beta") != mode+"-two" {
			http.Error(w, "unexpected request variables", http.StatusBadRequest)
			return
		}
		_, _ = fmt.Fprintf(w, "peirates-item-91-%s-response\n", mode)
	}
}

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("/wizard", validateRequest("wizard"))
	mux.HandleFunc("/direct", validateRequest("direct"))
	log.Fatal(http.ListenAndServe(":8080", mux))
}
