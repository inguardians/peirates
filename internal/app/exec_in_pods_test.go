package app

import (
	"bufio"
	"strings"
	"testing"
)

func TestReadExecMenuLinePreservesSubsequentResponses(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader("1\nprintf marker > /tmp/marker\ntarget-pod\n"))
	for _, expected := range []string{"1", "printf marker > /tmp/marker", "target-pod"} {
		actual, err := readExecMenuLine(reader)
		if err != nil {
			t.Fatalf("read menu response %q: %v", expected, err)
		}
		if actual != expected {
			t.Fatalf("read menu response %q, want %q", actual, expected)
		}
	}
}
