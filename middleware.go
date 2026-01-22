package surf

import (
	"github.com/enetx/g"
	"github.com/enetx/g/cmp"
)

// mw represents a middleware wrapper that holds the function itself,
// its execution priority, and the order in which it was added.
type mw[T any] struct {
	fn       func(T) error // Middleware function
	priority g.Int         // Execution priority (lower is higher priority)
	order    g.Int         // Insertion order (used to stabilize sorting)
}

// middleware is a generic middleware chain manager for type T.
// It uses a priority heap to manage the execution order of middleware functions.
type middleware[T any] struct {
	heap    *g.Heap[mw[T]] // Heap-ordered middleware functions
	counter g.Int          // Monotonic counter to track insertion order
}

// newMiddleware creates a new middleware manager for type T.
//
// Returns:
//   - *middleware[T]: a pointer to a new middleware instance
//
// Lower priority values execute earlier. For equal priorities, insertion order is preserved.
func newMiddleware[T any]() *middleware[T] {
	return &middleware[T]{
		heap: g.NewHeap(func(a, b mw[T]) cmp.Ordering {
			return a.priority.Cmp(b.priority).
				Then(a.order.Cmp(b.order))
		}),
	}
}

// add adds a middleware function to the chain with the specified priority.
//
// Parameters:
//   - priority int: determines execution order (lower means earlier execution)
//   - fn func(T) error: the middleware function that receives a context of type T
//
// Functions with the same priority are executed in the order they were added.
func (m *middleware[T]) add(priority g.Int, fn func(T) error) {
	m.heap.Push(mw[T]{fn, priority, m.counter})
	m.counter++
}

// run executes all middleware functions in priority order.
//
// Parameters:
//   - ctx T: the context value passed to each middleware function
//
// Returns:
//   - error: the first error encountered in the chain, or nil if all passed
//
// Note:
//   - A clone of the heap is used during execution to avoid mutating the original chain.
//   - Execution stops immediately if any middleware returns a non-nil error.
func (m *middleware[T]) run(ctx T) error {
	clone := m.heap.Clone()

	for !clone.IsEmpty() {
		item := clone.Pop().Some()
		if err := item.fn(ctx); err != nil {
			return err
		}
	}

	return nil
}
