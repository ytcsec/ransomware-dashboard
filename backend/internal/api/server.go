package api

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"ransomware-cti/internal/config"
	"ransomware-cti/internal/ingest"
	"ransomware-cti/internal/store"
	"ransomware-cti/internal/util"
)

type Server struct {
	db      *store.DB
	cfg     config.Config
	mu      sync.Mutex
	calisir bool
	sonrun  string
	sonhata string
	stats   *ingest.Stats
}

func New(db *store.DB, cfg config.Config) *Server {
	s := &Server{}
	s.db = db
	s.cfg = cfg
	return s
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", s.health)
	mux.HandleFunc("GET /api/summary", s.summary)
	mux.HandleFunc("GET /api/groups", s.groups)
	mux.HandleFunc("GET /api/countries", s.countries)
	mux.HandleFunc("GET /api/sectors", s.sectors)
	mux.HandleFunc("GET /api/attack-vectors", s.vectors)
	mux.HandleFunc("GET /api/techniques", s.techniques)
	mux.HandleFunc("GET /api/timeseries", s.timeseries)
	mux.HandleFunc("GET /api/severity", s.severity)
	mux.HandleFunc("GET /api/victims", s.victims)
	mux.HandleFunc("GET /api/ioc", s.ioc)
	mux.HandleFunc("GET /api/iocs", s.iocs)
	mux.HandleFunc("GET /api/ioc-groups", s.iocgroups)
	mux.HandleFunc("POST /api/refresh", s.refresh)
	mux.HandleFunc("GET /api/refresh/status", s.refreshstatus)
	return cors(mux)
}

func sendjson(w http.ResponseWriter, kod int, veri any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(kod)
	json.NewEncoder(w).Encode(veri)
}

func sendhata(w http.ResponseWriter, err error) {
	sendjson(w, 500, map[string]string{"error": err.Error()})
}

func getint(r *http.Request, isim string, def int) int {
	v := r.URL.Query().Get(isim)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func (s *Server) taban(r *http.Request) string {
	gun := 0
	w := r.URL.Query().Get("window")
	if w == "30d" {
		gun = 30
	} else if w == "180d" {
		gun = 180
	} else if w == "365d" {
		gun = 365
	} else {
		return ""
	}
	sontarih := s.db.MaxDate()
	if sontarih == "" {
		return ""
	}
	t, ok := util.ParseDate(sontarih)
	if !ok {
		return ""
	}
	return t.AddDate(0, 0, -gun).Format("2006-01-02")
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	meta, _ := s.db.Meta()
	sendjson(w, 200, map[string]any{"status": "ok", "meta": meta})
}

func (s *Server) summary(w http.ResponseWriter, r *http.Request) {
	sonuc, err := s.db.GetSummary(s.taban(r))
	if err != nil {
		sendhata(w, err)
		return
	}
	sonuc.Window = r.URL.Query().Get("window")
	sendjson(w, 200, sonuc)
}

func (s *Server) groups(w http.ResponseWriter, r *http.Request) {
	sonuc, err := s.db.Groups(getint(r, "limit", 12), s.taban(r))
	if err != nil {
		sendhata(w, err)
		return
	}
	sendjson(w, 200, sonuc)
}

func (s *Server) countries(w http.ResponseWriter, r *http.Request) {
	sonuc, err := s.db.Countries(getint(r, "limit", 40), s.taban(r))
	if err != nil {
		sendhata(w, err)
		return
	}
	sendjson(w, 200, sonuc)
}

func (s *Server) sectors(w http.ResponseWriter, r *http.Request) {
	sonuc, err := s.db.Sectors(getint(r, "limit", 20), s.taban(r))
	if err != nil {
		sendhata(w, err)
		return
	}
	sendjson(w, 200, sonuc)
}

func (s *Server) vectors(w http.ResponseWriter, r *http.Request) {
	sonuc, err := s.db.Vectors(s.taban(r))
	if err != nil {
		sendhata(w, err)
		return
	}
	sendjson(w, 200, sonuc)
}

func (s *Server) techniques(w http.ResponseWriter, r *http.Request) {
	sonuc, err := s.db.Techniques(getint(r, "limit", 12), s.taban(r))
	if err != nil {
		sendhata(w, err)
		return
	}
	sendjson(w, 200, sonuc)
}

func (s *Server) timeseries(w http.ResponseWriter, r *http.Request) {
	gunluk := r.URL.Query().Get("window") == "30d"
	sonuc, err := s.db.TimeSeries(s.taban(r), gunluk)
	if err != nil {
		sendhata(w, err)
		return
	}
	sendjson(w, 200, sonuc)
}

func (s *Server) severity(w http.ResponseWriter, r *http.Request) {
	sonuc, err := s.db.Severities(s.taban(r))
	if err != nil {
		sendhata(w, err)
		return
	}
	sendjson(w, 200, sonuc)
}

func (s *Server) victims(w http.ResponseWriter, r *http.Request) {
	var f store.VictimFilter
	f.Group = r.URL.Query().Get("group")
	f.Country = r.URL.Query().Get("country")
	f.Sector = r.URL.Query().Get("sector")
	f.SeverityMin = getint(r, "severity_min", 0)
	f.Query = r.URL.Query().Get("q")
	f.Limit = getint(r, "limit", 50)
	f.Offset = getint(r, "offset", 0)
	liste, toplam, err := s.db.Victims(f)
	if err != nil {
		sendhata(w, err)
		return
	}
	sendjson(w, 200, map[string]any{"total": toplam, "limit": f.Limit, "offset": f.Offset, "items": liste})
}

func (s *Server) ioc(w http.ResponseWriter, r *http.Request) {
	sonuc, err := s.db.IOCSearch(r.URL.Query().Get("q"))
	if err != nil {
		sendhata(w, err)
		return
	}
	sendjson(w, 200, sonuc)
}

func (s *Server) iocs(w http.ResponseWriter, r *http.Request) {
	var f store.IOCFilter
	f.Type = r.URL.Query().Get("type")
	f.Group = r.URL.Query().Get("group")
	f.Query = r.URL.Query().Get("q")
	f.Limit = getint(r, "limit", 50)
	f.Offset = getint(r, "offset", 0)
	liste, toplam, err := s.db.IOCList(f)
	if err != nil {
		sendhata(w, err)
		return
	}
	sendjson(w, 200, map[string]any{"total": toplam, "limit": f.Limit, "offset": f.Offset, "items": liste})
}

func (s *Server) iocgroups(w http.ResponseWriter, r *http.Request) {
	sonuc, err := s.db.IOCGroups()
	if err != nil {
		sendhata(w, err)
		return
	}
	sendjson(w, 200, sonuc)
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	basladi := s.StartRefresh()
	durum := s.durum()
	durum["started"] = basladi
	sendjson(w, 200, durum)
}

func (s *Server) refreshstatus(w http.ResponseWriter, r *http.Request) {
	sendjson(w, 200, s.durum())
}

func (s *Server) durum() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	m := map[string]any{}
	m["running"] = s.calisir
	m["last_run"] = s.sonrun
	m["error"] = s.sonhata
	if s.stats != nil {
		m["victims"] = s.stats.Victims
		m["iocs"] = s.stats.IOCs
		m["ioc_mode"] = s.stats.IOCMode
	}
	return m
}

func (s *Server) StartRefresh() bool {
	s.mu.Lock()
	if s.calisir {
		s.mu.Unlock()
		return false
	}
	s.calisir = true
	s.mu.Unlock()

	go func() {
		cfg := s.cfg
		cfg.Refresh = true
		log.Printf("veri tazeleme basladi")
		stats, err := ingest.Run(context.Background(), cfg)
		s.mu.Lock()
		s.calisir = false
		s.sonrun = time.Now().UTC().Format(time.RFC3339)
		if err != nil {
			s.sonhata = err.Error()
			log.Printf("veri tazeleme hatasi: %v", err)
		} else {
			s.sonhata = ""
			yeni := stats
			s.stats = &yeni
			log.Printf("veri tazeleme bitti: %d kurban", stats.Victims)
		}
		s.mu.Unlock()
	}()
	return true
}

func (s *Server) StartScheduler() {
	if s.cfg.RefreshHours <= 0 {
		return
	}
	log.Printf("otomatik tazeleme acik: her %d saatte bir", s.cfg.RefreshHours)
	go func() {
		t := time.NewTicker(time.Duration(s.cfg.RefreshHours) * time.Hour)
		defer t.Stop()
		for range t.C {
			s.StartRefresh()
		}
	}()
}

func (s *Server) SeedIfEmpty() {
	var adet int
	err := s.db.QueryRow("SELECT COUNT(*) FROM victims").Scan(&adet)
	if err == nil && adet == 0 {
		log.Printf("veritabani bos, ilk veri cekimi tetikleniyor")
		s.StartRefresh()
	}
}

func cors(sonraki http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		sonraki.ServeHTTP(w, r)
	})
}
