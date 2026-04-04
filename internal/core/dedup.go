package core

import (
	"bufio"
	"os"
	"path/filepath"
	"sync"
)

type DedupStore struct {
	mu       sync.Mutex
	seen     map[string]bool
	filePath string
}

func NewDedupStore(outputDir string) *DedupStore {
	fp := filepath.Join(outputDir, ".seen_urls")
	ds := &DedupStore{
		seen:     make(map[string]bool),
		filePath: fp,
	}
	ds.load()
	return ds
}

func (ds *DedupStore) load() {
	f, err := os.Open(ds.filePath)
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line != "" {
			ds.seen[line] = true
		}
	}
}

func (ds *DedupStore) IsSeen(url string) bool {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	return ds.seen[url]
}

func (ds *DedupStore) MarkSeen(url string) {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	ds.seen[url] = true
}

func (ds *DedupStore) Save() {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	f, err := os.Create(ds.filePath)
	if err != nil {
		return
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for url := range ds.seen {
		w.WriteString(url + "\n")
	}
	w.Flush()
}

func (ds *DedupStore) Count() int {
	ds.mu.Lock()
	defer ds.mu.Unlock()
	return len(ds.seen)
}