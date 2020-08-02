package entropy

import (
	"sync"
	"testing"

	"github.com/oklog/ulid/v2"
)

func TestEntropy_MonotonicReader(t *testing.T) {
	var err error

	entropy := New()
	wg := sync.WaitGroup{}
	concurrency := 50
	idc := make(chan string, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			id, e := ulid.New(ulid.Now(), entropy)
			if e != nil {
				err = e
			}
			if err == nil {
				str := id.String()
				idc <- str
			}
			wg.Done()
		}()
	}

	wg.Wait()
	close(idc)

	foundIds := map[string]bool{}
	for id := range idc {
		if foundIds[id] {
			t.Error("duplicate ULID found", id)
		} else {
			foundIds[id] = true
		}
	}
}
