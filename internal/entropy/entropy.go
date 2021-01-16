// Package entropy provides safe entropy to use in concurrent tasks
package entropy

import (
	"math/rand"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

// safeMonotonicReader provides a safe entropy to be used in concurrent tasks.
// https://github.com/oklog/ulid/blob/0d4fda9d6345755e157a256fd33d48556c5f4a7a/ulid_test.go#L633-L636
type safeMonotonicReader struct {
	mtx sync.Mutex
	ulid.MonotonicReader
}

func (r *safeMonotonicReader) MonotonicRead(ms uint64, p []byte) (err error) {
	r.mtx.Lock()
	err = r.MonotonicReader.MonotonicRead(ms, p)
	r.mtx.Unlock()

	return err
}

// New returns a new MonotonicReader.
func New() ulid.MonotonicReader {
	// nolint:gosec // crypto/rand not necessary for ULID generation
	monotonic := ulid.Monotonic(rand.New(
		rand.NewSource(time.Now().UnixNano()),
	), 0)

	return &safeMonotonicReader{MonotonicReader: monotonic}
}
