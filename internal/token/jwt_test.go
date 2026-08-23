package token

import "testing"

func TestDecodeAndPrettyPrintPayload(t *testing.T) {
	jwt := Decode("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSIsIm4iOjF9.signature")
	if jwt.Header != `{"alg":"HS256"}` || jwt.Payload != `{"sub":"alice","n":1}` || jwt.Signature != "signature" {
		t.Fatalf("unexpected JWT: %#v", jwt)
	}
	if got, want := jwt.PrettyPrintPayload(), "{\n  \"sub\": \"alice\",\n  \"n\": 1\n}"; got != want {
		t.Fatalf("PrettyPrintPayload() = %q, want %q", got, want)
	}
}

func TestDecodePanicsForMalformedInput(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Decode did not panic")
		}
	}()
	Decode("only.two")
}

func TestDecodePanicsForInvalidBase64(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Decode did not panic")
		}
	}()
	Decode("%%.e30.signature")
}

func TestPrettyPrintPayloadRejectsInvalidJSON(t *testing.T) {
	if got := (&JWT{Payload: "not-json"}).PrettyPrintPayload(); got != "Error pretty printing JSON" {
		t.Fatalf("got %q", got)
	}
}
