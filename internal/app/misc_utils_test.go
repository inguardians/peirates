package app

import (
	"math/rand"
	"os"
	"testing"
)

func TestRandSeqLengthAndAlphabet(t *testing.T) {
	rand.Seed(1)
	if got := randSeq(0); got != "" {
		t.Fatalf("zero length = %q", got)
	}
	got := randSeq(64)
	if len(got) != 64 {
		t.Fatalf("length = %d", len(got))
	}
	for _, r := range got {
		if r < 'a' || r > 'z' {
			t.Fatalf("non-lowercase rune %q", r)
		}
	}
}

func TestPauseToHitEnterNonInteractive(t *testing.T) { pauseToHitEnter(false) }

func TestReadLineHelpers(t *testing.T) {
	original := os.Stdin
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.Stdin = original
		_ = r.Close()
	})
	os.Stdin = r
	if _, err := w.WriteString("  value  \n"); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	if got, err := ReadLineStripWhitespace(); err != nil || got != "value" {
		t.Fatalf("ReadLineStripWhitespace() = %q, %v", got, err)
	}
}
