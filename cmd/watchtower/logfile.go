package main

import (
	"fmt"
	"os"
	"sync"
)

// rotatingFile is an io.Writer keeping path plus keep-1 older copies, each at most max bytes.
type rotatingFile struct {
	path string
	max  int64
	keep int

	mu   sync.Mutex
	f    *os.File
	size int64
}

func openRotating(path string, max int64, keep int) (*rotatingFile, error) {
	r := &rotatingFile{path: path, max: max, keep: keep}
	return r, r.open()
}

func (r *rotatingFile) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	r.f, r.size = f, st.Size()
	return nil
}

func (r *rotatingFile) name(i int) string {
	if i == 0 {
		return r.path
	}
	return fmt.Sprintf("%s.%d", r.path, i)
}

func (r *rotatingFile) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size > 0 && r.size+int64(len(p)) > r.max {
		r.f.Close()
		for i := r.keep - 1; i > 0; i-- {
			os.Rename(r.name(i-1), r.name(i)) // a missing older copy is fine
		}
		if err := r.open(); err != nil {
			return 0, err
		}
	}
	n, err := r.f.Write(p)
	r.size += int64(n)
	return n, err
}
