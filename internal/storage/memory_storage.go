package storage

import (
	"sync"

	proxymodels "github.com/BetterCallFirewall/Hackerecon/internal/models/proxy"
)

type MemoryStorage struct {
	requests map[string]*proxymodels.RequestData
	mu       sync.RWMutex
}

func NewMemoryStorage() *MemoryStorage {
	return &MemoryStorage{
		requests: make(map[string]*proxymodels.RequestData),
	}
}

func (s *MemoryStorage) StoreRequest(req *proxymodels.RequestData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.requests[req.ID] = req
}

func (s *MemoryStorage) GetRequest(id string) (*proxymodels.RequestData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	req, ok := s.requests[id]
	return req, ok
}

func (s *MemoryStorage) GetAllRequests() []*proxymodels.RequestData {
	s.mu.RLock()
	defer s.mu.RUnlock()

	requests := make([]*proxymodels.RequestData, 0, len(s.requests))
	for _, req := range s.requests {
		requests = append(requests, req)
	}
	return requests
}

func (s *MemoryStorage) DeleteRequest(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.requests, id)
}
