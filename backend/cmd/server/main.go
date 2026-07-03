package main

import (
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"ransomware-cti/internal/api"
	"ransomware-cti/internal/config"
	"ransomware-cti/internal/store"
)

func main() {
	saglik := flag.Bool("healthcheck", false, "saglik kontrolu yapip cik")
	flag.Parse()

	log.SetFlags(log.Ltime)
	cfg := config.Load()

	if *saglik {
		os.Exit(sagliktesti(cfg.Addr))
	}

	db, err := store.Open(cfg.DbPath)
	if err != nil {
		log.Fatalf("veritabani acilamadi (%s): %v", cfg.DbPath, err)
	}
	defer db.Close()
	err = db.Migrate()
	if err != nil {
		log.Fatalf("tablolar olusturulamadi: %v", err)
	}

	server := api.New(db, cfg)
	server.SeedIfEmpty()
	server.StartScheduler()

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           server.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	log.Printf("CTI API dinliyor %s (db=%s)", cfg.Addr, cfg.DbPath)
	err = srv.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("sunucu hatasi: %v", err)
	}
}

func sagliktesti(addr string) int {
	client := http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get("http://127.0.0.1" + addr + "/api/health")
	if err != nil {
		return 1
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)
	if resp.StatusCode == 200 {
		return 0
	}
	return 1
}
