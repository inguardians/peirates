package modules

import "testing"

func TestRegistryDispatch(t *testing.T) {
	registry := NewRegistry()
	called := 0
	registry.Register(func() Result { called++; return Refresh }, "one", "alias")
	if result, ok := registry.Run("alias"); !ok || result != Refresh || called != 1 {
		t.Fatalf("Run(alias) = %v, %v; called=%d", result, ok, called)
	}
	if _, ok := registry.Run("missing"); ok {
		t.Fatal("missing handler was reported as registered")
	}
}
