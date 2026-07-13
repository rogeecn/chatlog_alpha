package http

import "testing"

func TestLoopbackCompatAddressNormalizesWildcardBindings(t *testing.T) {
	tests := map[string]string{
		"0.0.0.0:5030": "127.0.0.1:5030",
		"[::]:5030":    "127.0.0.1:5030",
		":5030":        "127.0.0.1:5030",
		"127.0.0.1:9":  "127.0.0.1:9",
	}
	for input, want := range tests {
		if got := loopbackCompatAddress(input); got != want {
			t.Fatalf("loopbackCompatAddress(%q) = %q, want %q", input, got, want)
		}
	}
}
