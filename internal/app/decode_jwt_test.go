package app

import "testing"

func TestDecodeJWTAndPrettyPrintPayload(t *testing.T) {
	jwt := decodeJWT("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSIsIm4iOjF9.signature")
	if jwt.Header != `{"alg":"HS256"}` || jwt.Payload != `{"sub":"alice","n":1}` || jwt.Signature != "signature" {
		t.Fatalf("unexpected JWT: %#v", jwt)
	}
	if got, want := jwt.PrettyPrintPayload(), "{\n  \"sub\": \"alice\",\n  \"n\": 1\n}"; got != want {
		t.Fatalf("PrettyPrintPayload() = %q, want %q", got, want)
	}
}

func TestDecodeJWTPanicsForMalformedInput(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("decodeJWT did not panic")
		}
	}()
	decodeJWT("only.two")
}

func TestDecodeBase64PanicsForInvalidInput(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("decodeBase64 did not panic")
		}
	}()
	decodeBase64("%%")
}

func TestPrettyPrintPayloadRejectsInvalidJSON(t *testing.T) {
	if got := (&JWT{Payload: "not-json"}).PrettyPrintPayload(); got != "Error pretty printing JSON" {
		t.Fatalf("got %q", got)
	}
}
