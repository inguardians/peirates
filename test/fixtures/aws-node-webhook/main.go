// The webhook is a controlled Kind fixture, not an AWS IAM authenticator.
// It independently checks SigV4 for fixed, non-AWS credentials and maps only
// that signature to the disposable node. It never contacts STS.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const fixtureAccessKey = "AKIDPEIRATESKINDTEST"
const fixtureSecret = "peirates-kind-fixture-secret-not-an-aws-credential"
const fixtureSession = "peirates-kind-fixture-session"

func digest(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }
func mac(key []byte, s string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(s))
	return h.Sum(nil)
}

func authentic(token, cluster string) bool {
	if !strings.HasPrefix(token, "k8s-aws-v1.") {
		return false
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, "k8s-aws-v1."))
	if err != nil {
		return false
	}
	u, err := url.Parse(string(data))
	if err != nil || u.Scheme != "https" || u.Host != "sts.us-west-2.amazonaws.com" || u.Path != "/" || u.User != nil || u.Fragment != "" {
		return false
	}
	q := u.Query()
	stamp, err := time.Parse("20060102T150405Z", q.Get("X-Amz-Date"))
	if err != nil || time.Since(stamp) < -time.Minute || time.Since(stamp) > 14*time.Minute {
		return false
	}
	scope := strings.Split(q.Get("X-Amz-Credential"), "/")
	if len(scope) != 5 || scope[0] != fixtureAccessKey || scope[1] != stamp.Format("20060102") || scope[2] != "us-west-2" || scope[3] != "sts" || scope[4] != "aws4_request" {
		return false
	}
	if q.Get("X-Amz-Expires") != "60" || q.Get("Action") != "GetCallerIdentity" || q.Get("Version") != "2011-06-15" || q.Get("X-Amz-Security-Token") != fixtureSession || q.Get("X-Amz-SignedHeaders") != "host;x-k8s-aws-id" || q.Get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256" {
		return false
	}
	signature, err := hex.DecodeString(q.Get("X-Amz-Signature"))
	if err != nil {
		return false
	}
	q.Del("X-Amz-Signature")
	query := strings.ReplaceAll(q.Encode(), "+", "%20")
	canonical := "GET\n/\n" + query + "\nhost:" + u.Host + "\nx-k8s-aws-id:" + cluster + "\n\nhost;x-k8s-aws-id\n" + digest("")
	toSign := "AWS4-HMAC-SHA256\n" + q.Get("X-Amz-Date") + "\n" + strings.Join(scope[1:], "/") + "\n" + digest(canonical)
	key := mac(mac(mac(mac([]byte("AWS4"+fixtureSecret), scope[1]), scope[2]), "sts"), "aws4_request")
	return hmac.Equal(signature, mac(key, toSign))
}

func main() {
	cert := flag.String("cert", "", "TLS certificate")
	key := flag.String("key", "", "TLS key")
	cluster := flag.String("cluster", "", "accepted cluster binding")
	node := flag.String("node", "", "disposable node username suffix")
	flag.Parse()
	if *cluster == "" || *node == "" || *cert == "" || *key == "" {
		log.Fatal("all fixture flags are required")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/authenticate", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Spec struct {
				Token string `json:"token"`
			} `json:"spec"`
		}
		if r.Method != http.MethodPost || json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&req) != nil {
			http.Error(w, "bad review", http.StatusBadRequest)
			return
		}
		status := map[string]any{"authenticated": false}
		if authentic(req.Spec.Token, *cluster) {
			status = map[string]any{"authenticated": true, "user": map[string]any{"username": "system:node:" + *node, "groups": []string{"system:nodes", "system:authenticated"}}}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"apiVersion": "authentication.k8s.io/v1beta1", "kind": "TokenReview", "status": status})
	})
	server := &http.Server{Addr: "127.0.0.1:9443", Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	fmt.Println("controlled node authentication webhook ready")
	log.Fatal(server.ListenAndServeTLS(*cert, *key))
}
