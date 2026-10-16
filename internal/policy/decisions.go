package policy

import (
	"sync"
	"sync/atomic"

	"github.com/strongdm/leash/internal/engine"
)

// DecisionSnapshot is one published engine and the policy generation it was
// built from.
type DecisionSnapshot struct {
	Engine     *engine.Engine
	Generation uint64
}

// Decisions holds the engine every request-time consumer (the MITM proxy,
// the plugin authz socket) evaluates against (#142). Publish swaps in the
// engine of a newly active policy, bumps the generation and hands it to
// each consumer under one lock, so all consumers see the same policy, in
// order, and no decision sees half a reload.
type Decisions struct {
	mu         sync.Mutex // orders concurrent Publish calls
	current    atomic.Pointer[DecisionSnapshot]
	generation uint64
}

// Publish makes eng current, hands it to each consumer and returns it.
func (d *Decisions) Publish(eng *engine.Engine, consumers ...func(*engine.Engine)) *engine.Engine {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.generation++
	d.current.Store(&DecisionSnapshot{Engine: eng, Generation: d.generation})
	for _, consume := range consumers {
		if consume != nil {
			consume(eng)
		}
	}
	return eng
}

// Current returns the current snapshot, or nil before the first Publish.
func (d *Decisions) Current() *DecisionSnapshot {
	if d == nil {
		return nil
	}
	return d.current.Load()
}
