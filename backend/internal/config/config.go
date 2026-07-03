package config

import (
	"os"
	"strconv"
)

type Config struct {
	RansomBase   string
	AbuseKey     string
	From         string
	DbPath       string
	DataDir      string
	Throttle     int
	Retry        int
	Agent        string
	Refresh      bool
	Addr         string
	RefreshHours int
	IocLimit     int
}

func env(key string, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func envint(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}

func Load() Config {
	var c Config
	c.DataDir = env("DATA_DIR", "data")
	c.RansomBase = env("RANSOMWARELIVE_BASE", "https://api.ransomware.live/v2")
	c.AbuseKey = os.Getenv("ABUSECH_AUTH_KEY")
	c.From = env("WINDOW_FROM", "2024-07")
	c.DbPath = env("DB_PATH", c.DataDir+"/cti.db")
	c.Throttle = envint("THROTTLE_MS", 1200)
	c.Retry = envint("MAX_RETRY", 5)
	c.Agent = env("USER_AGENT", "ransomware-cti-dashboard/1.0 (research; contact: local)")
	c.Refresh = env("REFRESH", "false") == "true"
	c.Addr = env("API_ADDR", ":8080")
	c.RefreshHours = envint("REFRESH_INTERVAL_HOURS", 0)
	c.IocLimit = envint("IOC_PER_GROUP", 250)
	return c
}
