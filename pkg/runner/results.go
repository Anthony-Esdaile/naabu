package runner

import "sync"

type KVResults struct {
	sync.RWMutex
	m map[string][]int
}

func NewKVResults() *KVResults {
	m := make(map[string][]int)
	return &KVResults{m: m}
}

func (r *KVResults) AddPort(host string, port int) {
	r.Lock()
	defer r.Unlock()

	r.m[host] = append(r.m[host], port)
}

func (r *KVResults) SetPorts(host string, ports []int) {
	r.Lock()
	defer r.Unlock()

	r.m[host] = ports
}

func (r *KVResults) Has(host string, port int) bool {
	r.RLock()
	defer r.RUnlock()

	if p, ok := r.m[host]; ok {
		return sliceIntContains(p, port)
	}

	return false
}
