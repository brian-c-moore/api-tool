package chain

import (
	"os"
	"strings"
	"sync"
)

// State manages variables during a chain execution.
// It's implemented as a thread-safe map.
type State struct {
	mu   sync.RWMutex
	vars map[string]string
}

// NewState creates an empty chain state.
func NewState() *State {
	return &State{
		vars: make(map[string]string),
	}
}

// Set stores a variable in the state.
func (s *State) Set(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.vars[key] = value
}

// Get retrieves a variable from the state.
func (s *State) Get(key string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	val, ok := s.vars[key]
	return val, ok
}

// GetAll returns a copy of all variables in the state.
// This is useful for template execution which needs a map.
func (s *State) GetAll() map[string]string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	// Create a copy to avoid race conditions if the caller modifies the map
	copiedVars := make(map[string]string, len(s.vars))
	for k, v := range s.vars {
		copiedVars[k] = v
	}
	return copiedVars
}

// MergeMap adds all key-value pairs from the given map to the state,
// potentially overwriting existing keys.
func (s *State) MergeMap(newVars map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, value := range newVars {
		s.vars[key] = value
	}
}

// MergeOSEnv reads all OS environment variables and adds them to the state,
// potentially overwriting existing keys.
func (s *State) MergeOSEnv() { // <--- FIX: Moved definition line inside function
	s.mu.Lock() // <--- FIX: Lock was outside the function scope before
	defer s.mu.Unlock()
	for _, envVar := range os.Environ() {
		parts := strings.SplitN(envVar, "=", 2)
		if len(parts) == 2 {
			// Only add if key is non-empty
			if parts[0] != "" {
				s.vars[parts[0]] = parts[1]
			}
		}
	}
}