package enrich

import (
	"container/list"
	"context"
	"net"
	"sync"
	"time"
)

type WorkerConfig struct {
	MaxEntries   int
	CacheTTL     time.Duration
	NegativeTTL  time.Duration
	PTRTimeout   time.Duration
	PTRRateLimit int
	VerifyFCRDNS bool
	Workers      int
}

type WorkerValue struct {
	Result    Result `json:"result"`
	Pending   bool   `json:"pending"`
	Error     string `json:"error,omitempty"`
	UpdatedAt int64  `json:"updated_unix,omitempty"`
	AgeSec    int64  `json:"age_sec,omitempty"`
}

type Worker struct {
	enr *Enricher
	cfg WorkerConfig

	mu       sync.Mutex
	items    map[string]*list.Element
	lru      *list.List
	inFlight map[string]struct{}
	queue    chan string
	rateTick <-chan time.Time
}

type workerEntry struct {
	ip       string
	value    WorkerValue
	expires  time.Time
	negative bool
}

func NewWorker(enr *Enricher, cfg WorkerConfig) *Worker {
	if cfg.MaxEntries <= 0 {
		cfg.MaxEntries = 4096
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = time.Hour
	}
	if cfg.NegativeTTL <= 0 {
		cfg.NegativeTTL = 5 * time.Minute
	}
	if cfg.PTRTimeout <= 0 {
		cfg.PTRTimeout = time.Second
	}
	if cfg.PTRRateLimit <= 0 {
		cfg.PTRRateLimit = 100
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 2
	}
	w := &Worker{
		enr:      enr,
		cfg:      cfg,
		items:    make(map[string]*list.Element),
		lru:      list.New(),
		inFlight: make(map[string]struct{}),
		queue:    make(chan string, 2048),
		rateTick: time.NewTicker(time.Second / time.Duration(cfg.PTRRateLimit)).C,
	}
	for i := 0; i < cfg.Workers; i++ {
		go w.run()
	}
	return w
}

func (w *Worker) Get(ip string) WorkerValue {
	if net.ParseIP(ip) == nil {
		return WorkerValue{Error: "invalid ip"}
	}
	now := time.Now()
	w.mu.Lock()
	if el, ok := w.items[ip]; ok {
		e := el.Value.(*workerEntry)
		if now.Before(e.expires) {
			w.lru.MoveToFront(el)
			v := e.value
			if e.value.UpdatedAt > 0 {
				v.AgeSec = now.Unix() - e.value.UpdatedAt
			}
			w.mu.Unlock()
			return v
		}
	}
	w.mu.Unlock()

	base := WorkerValue{Pending: true}
	if w.enr != nil {
		base.Result = w.enr.LookupLocal(ip)
	}
	w.store(ip, base, false)
	w.enqueue(ip)
	return base
}

func (w *Worker) enqueue(ip string) {
	w.mu.Lock()
	if _, ok := w.inFlight[ip]; ok {
		w.mu.Unlock()
		return
	}
	w.inFlight[ip] = struct{}{}
	w.mu.Unlock()
	select {
	case w.queue <- ip:
	default:
		w.mu.Lock()
		delete(w.inFlight, ip)
		w.mu.Unlock()
	}
}

func (w *Worker) run() {
	for ip := range w.queue {
		<-w.rateTick
		w.resolvePTR(ip)
		w.mu.Lock()
		delete(w.inFlight, ip)
		w.mu.Unlock()
	}
}

func (w *Worker) resolvePTR(ip string) {
	v := WorkerValue{}
	if w.enr != nil {
		v.Result = w.enr.LookupLocal(ip)
		ctx, cancel := context.WithTimeout(context.Background(), w.cfg.PTRTimeout)
		ptr, err := w.enr.LookupPTR(ctx, ip, w.cfg.VerifyFCRDNS)
		cancel()
		if err != nil {
			v.Error = err.Error()
		} else {
			v.Result.PTR = ptr
		}
	}
	v.Pending = false
	v.UpdatedAt = time.Now().Unix()
	neg := v.Error != "" || v.Result.PTR == ""
	w.store(ip, v, neg)
}

func (w *Worker) store(ip string, v WorkerValue, negative bool) {
	now := time.Now()
	ttl := w.cfg.CacheTTL
	if negative {
		ttl = w.cfg.NegativeTTL
	}
	ent := &workerEntry{ip: ip, value: v, expires: now.Add(ttl), negative: negative}

	w.mu.Lock()
	defer w.mu.Unlock()
	if el, ok := w.items[ip]; ok {
		el.Value = ent
		w.lru.MoveToFront(el)
	} else {
		el := w.lru.PushFront(ent)
		w.items[ip] = el
	}
	for len(w.items) > w.cfg.MaxEntries {
		back := w.lru.Back()
		if back == nil {
			break
		}
		be := back.Value.(*workerEntry)
		delete(w.items, be.ip)
		w.lru.Remove(back)
	}
}
