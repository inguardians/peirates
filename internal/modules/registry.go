// Package modules provides application-composed capability dispatch.
package modules

// Result controls the app loop after a module handler returns.
type Result uint8

const (
	// Continue applies the normal pause/clear or noninteractive exit behavior.
	Continue Result = iota
	// Refresh immediately redraws the interactive menu.
	Refresh
)

// Handler executes one canonical module command.
type Handler func() Result

// Registry maps canonical command names to handlers.
type Registry struct{ handlers map[string]Handler }

// NewRegistry creates an empty handler registry.
func NewRegistry() *Registry { return &Registry{handlers: make(map[string]Handler)} }

// Register associates names with handler.
func (r *Registry) Register(handler Handler, names ...string) {
	for _, name := range names {
		r.handlers[name] = handler
	}
}

// Run executes name when registered.
func (r *Registry) Run(name string) (Result, bool) {
	handler, ok := r.handlers[name]
	if !ok {
		return Continue, false
	}
	return handler(), true
}
