package store

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"

	"ransomware-cti/internal/model"

	_ "modernc.org/sqlite"
)

type DB struct {
	*sql.DB
}

var tablolar = `
CREATE TABLE IF NOT EXISTS victims (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	date          TEXT NOT NULL,
	ransomware_group TEXT NOT NULL,
	country       TEXT,
	country_name  TEXT,
	target_sector TEXT,
	attack_vector TEXT,
	technique_id  TEXT,
	technique     TEXT,
	severity      INTEGER NOT NULL,
	ioc_ip        TEXT,
	ioc_hash      TEXT,
	victim        TEXT,
	description   TEXT,
	domain        TEXT,
	claim_url     TEXT,
	source_url    TEXT
);
CREATE INDEX IF NOT EXISTS idx_victims_group   ON victims(ransomware_group);
CREATE INDEX IF NOT EXISTS idx_victims_country ON victims(country);
CREATE INDEX IF NOT EXISTS idx_victims_sector  ON victims(target_sector);
CREATE INDEX IF NOT EXISTS idx_victims_date    ON victims(date);
CREATE INDEX IF NOT EXISTS idx_victims_sev     ON victims(severity);

CREATE TABLE IF NOT EXISTS iocs (
	id            INTEGER PRIMARY KEY AUTOINCREMENT,
	value         TEXT NOT NULL,
	type          TEXT NOT NULL,
	ransomware_group TEXT NOT NULL,
	malware_family TEXT,
	confidence    INTEGER,
	first_seen    TEXT,
	source        TEXT
);
CREATE INDEX IF NOT EXISTS idx_iocs_value ON iocs(value);
CREATE INDEX IF NOT EXISTS idx_iocs_group ON iocs(ransomware_group);
CREATE INDEX IF NOT EXISTS idx_iocs_type  ON iocs(type);

CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value TEXT
);
`

func Open(yol string) (*DB, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=busy_timeout(8000)&_pragma=foreign_keys(1)", filepath.ToSlash(yol))
	sdb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	err = sdb.Ping()
	if err != nil {
		return nil, err
	}
	return &DB{sdb}, nil
}

func (db *DB) Migrate() error {
	_, err := db.Exec(tablolar)
	return err
}

type GroupStat struct {
	Group       string  `json:"ransomware_group"`
	Count       int     `json:"count"`
	AvgSeverity float64 `json:"avg_severity"`
}

type CountryStat struct {
	Country     string  `json:"country"`
	CountryName string  `json:"country_name"`
	Count       int     `json:"count"`
	AvgSeverity float64 `json:"avg_severity"`
}

type SectorStat struct {
	Sector      string  `json:"target_sector"`
	Count       int     `json:"count"`
	AvgSeverity float64 `json:"avg_severity"`
}

type VectorStat struct {
	AttackVector string `json:"attack_vector"`
	Count        int    `json:"count"`
}

type TechniqueStat struct {
	TechniqueID string `json:"technique_id"`
	Technique   string `json:"technique"`
	Count       int    `json:"count"`
}

type TimePoint struct {
	Period      string  `json:"period"`
	Count       int     `json:"count"`
	AvgSeverity float64 `json:"avg_severity"`
}

type SeverityBin struct {
	Severity int `json:"severity"`
	Count    int `json:"count"`
}

type Summary struct {
	VictimCount  int               `json:"victim_count"`
	GroupCount   int               `json:"group_count"`
	CountryCount int               `json:"country_count"`
	SectorCount  int               `json:"sector_count"`
	IOCCount     int               `json:"ioc_count"`
	AvgSeverity  float64           `json:"avg_severity"`
	HighSevCount int               `json:"high_severity_count"`
	DateMin      string            `json:"date_min"`
	DateMax      string            `json:"date_max"`
	Last30dCount int               `json:"last30d_count"`
	Window       string            `json:"window"`
	Meta         map[string]string `json:"meta"`
}

func (db *DB) MaxDate() string {
	var d string
	db.QueryRow("SELECT COALESCE(MAX(date),'') FROM victims").Scan(&d)
	return d
}

func (db *DB) Meta() (map[string]string, error) {
	rows, err := db.Query("SELECT key, value FROM meta")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sonuc := map[string]string{}
	for rows.Next() {
		var k string
		var v string
		err = rows.Scan(&k, &v)
		if err != nil {
			return nil, err
		}
		sonuc[k] = v
	}
	return sonuc, rows.Err()
}

func (db *DB) GetSummary(taban string) (Summary, error) {
	var s Summary
	where := ""
	args := []any{}
	if taban != "" {
		where = " WHERE date >= ?"
		args = append(args, taban)
	}
	sorgu := `SELECT
		COUNT(*),
		COUNT(DISTINCT ransomware_group),
		COUNT(DISTINCT NULLIF(country,'')),
		COUNT(DISTINCT NULLIF(target_sector,'')),
		COALESCE(AVG(severity),0),
		COALESCE(SUM(CASE WHEN severity>=8 THEN 1 ELSE 0 END),0),
		COALESCE(MIN(date),''),
		COALESCE(MAX(date),'')
		FROM victims` + where
	err := db.QueryRow(sorgu, args...).Scan(&s.VictimCount, &s.GroupCount, &s.CountryCount, &s.SectorCount,
		&s.AvgSeverity, &s.HighSevCount, &s.DateMin, &s.DateMax)
	if err != nil {
		return s, err
	}
	db.QueryRow("SELECT COUNT(*) FROM iocs").Scan(&s.IOCCount)
	sontarih := db.MaxDate()
	if sontarih != "" {
		db.QueryRow("SELECT COUNT(*) FROM victims WHERE date >= date(?, '-30 day')", sontarih).Scan(&s.Last30dCount)
	}
	m, _ := db.Meta()
	s.Meta = m
	return s, nil
}

func (db *DB) Groups(limit int, taban string) ([]GroupStat, error) {
	where := ""
	args := []any{}
	if taban != "" {
		where = " WHERE date >= ?"
		args = append(args, taban)
	}
	args = append(args, limit)
	rows, err := db.Query("SELECT ransomware_group, COUNT(*) c, AVG(severity) FROM victims"+where+
		" GROUP BY ransomware_group ORDER BY c DESC LIMIT ?", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sonuc := []GroupStat{}
	for rows.Next() {
		var g GroupStat
		err = rows.Scan(&g.Group, &g.Count, &g.AvgSeverity)
		if err != nil {
			return nil, err
		}
		sonuc = append(sonuc, g)
	}
	return sonuc, rows.Err()
}

func (db *DB) Countries(limit int, taban string) ([]CountryStat, error) {
	where := " WHERE country <> ''"
	args := []any{}
	if taban != "" {
		where = where + " AND date >= ?"
		args = append(args, taban)
	}
	args = append(args, limit)
	rows, err := db.Query("SELECT country, COALESCE(MAX(country_name),''), COUNT(*) c, AVG(severity) FROM victims"+where+
		" GROUP BY country ORDER BY c DESC LIMIT ?", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sonuc := []CountryStat{}
	for rows.Next() {
		var c CountryStat
		err = rows.Scan(&c.Country, &c.CountryName, &c.Count, &c.AvgSeverity)
		if err != nil {
			return nil, err
		}
		sonuc = append(sonuc, c)
	}
	return sonuc, rows.Err()
}

func (db *DB) Sectors(limit int, taban string) ([]SectorStat, error) {
	where := " WHERE target_sector <> ''"
	args := []any{}
	if taban != "" {
		where = where + " AND date >= ?"
		args = append(args, taban)
	}
	args = append(args, limit)
	rows, err := db.Query("SELECT target_sector, COUNT(*) c, AVG(severity) FROM victims"+where+
		" GROUP BY target_sector ORDER BY c DESC LIMIT ?", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sonuc := []SectorStat{}
	for rows.Next() {
		var s SectorStat
		err = rows.Scan(&s.Sector, &s.Count, &s.AvgSeverity)
		if err != nil {
			return nil, err
		}
		sonuc = append(sonuc, s)
	}
	return sonuc, rows.Err()
}

func (db *DB) Vectors(taban string) ([]VectorStat, error) {
	where := " WHERE attack_vector <> ''"
	args := []any{}
	if taban != "" {
		where = where + " AND date >= ?"
		args = append(args, taban)
	}
	rows, err := db.Query("SELECT attack_vector, COUNT(*) c FROM victims"+where+
		" GROUP BY attack_vector ORDER BY c DESC", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sonuc := []VectorStat{}
	for rows.Next() {
		var v VectorStat
		err = rows.Scan(&v.AttackVector, &v.Count)
		if err != nil {
			return nil, err
		}
		sonuc = append(sonuc, v)
	}
	return sonuc, rows.Err()
}

func (db *DB) Techniques(limit int, taban string) ([]TechniqueStat, error) {
	where := " WHERE technique_id <> ''"
	args := []any{}
	if taban != "" {
		where = where + " AND date >= ?"
		args = append(args, taban)
	}
	args = append(args, limit)
	rows, err := db.Query("SELECT technique_id, COALESCE(MAX(technique),''), COUNT(*) c FROM victims"+where+
		" GROUP BY technique_id ORDER BY c DESC LIMIT ?", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sonuc := []TechniqueStat{}
	for rows.Next() {
		var t TechniqueStat
		err = rows.Scan(&t.TechniqueID, &t.Technique, &t.Count)
		if err != nil {
			return nil, err
		}
		sonuc = append(sonuc, t)
	}
	return sonuc, rows.Err()
}

func (db *DB) TimeSeries(taban string, gunluk bool) ([]TimePoint, error) {
	kolon := "substr(date,1,7)"
	enaz := "7"
	if gunluk {
		kolon = "substr(date,1,10)"
		enaz = "10"
	}
	where := " WHERE length(date) >= " + enaz
	args := []any{}
	if taban != "" {
		where = where + " AND date >= ?"
		args = append(args, taban)
	}
	rows, err := db.Query("SELECT "+kolon+" p, COUNT(*) c, AVG(severity) FROM victims"+where+
		" GROUP BY p ORDER BY p", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sonuc := []TimePoint{}
	for rows.Next() {
		var t TimePoint
		err = rows.Scan(&t.Period, &t.Count, &t.AvgSeverity)
		if err != nil {
			return nil, err
		}
		sonuc = append(sonuc, t)
	}
	return sonuc, rows.Err()
}

func (db *DB) Severities(taban string) ([]SeverityBin, error) {
	where := ""
	args := []any{}
	if taban != "" {
		where = " WHERE date >= ?"
		args = append(args, taban)
	}
	rows, err := db.Query("SELECT severity, COUNT(*) FROM victims"+where+
		" GROUP BY severity ORDER BY severity", args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sonuc := []SeverityBin{}
	for rows.Next() {
		var b SeverityBin
		err = rows.Scan(&b.Severity, &b.Count)
		if err != nil {
			return nil, err
		}
		sonuc = append(sonuc, b)
	}
	return sonuc, rows.Err()
}

var victimkolonlar = `id, date, ransomware_group, country, country_name, target_sector, attack_vector,
	technique_id, technique, severity, ioc_ip, ioc_hash, victim, description, domain, claim_url, source_url`

func victimoku(rows *sql.Rows) []model.Victim {
	sonuc := []model.Victim{}
	for rows.Next() {
		var v model.Victim
		err := rows.Scan(&v.ID, &v.Date, &v.Group, &v.Country, &v.CountryName, &v.Sector,
			&v.AttackVector, &v.TechniqueID, &v.TechniqueName, &v.Severity, &v.IOCIP, &v.IOCHash,
			&v.Org, &v.Description, &v.Domain, &v.ClaimURL, &v.SourceURL)
		if err != nil {
			continue
		}
		sonuc = append(sonuc, v)
	}
	return sonuc
}

type VictimFilter struct {
	Group       string
	Country     string
	Sector      string
	SeverityMin int
	Query       string
	Limit       int
	Offset      int
}

func (db *DB) Victims(f VictimFilter) ([]model.Victim, int, error) {
	where := " WHERE 1=1"
	args := []any{}
	if f.Group != "" {
		where = where + " AND ransomware_group = ?"
		args = append(args, f.Group)
	}
	if f.Country != "" {
		where = where + " AND country = ?"
		args = append(args, f.Country)
	}
	if f.Sector != "" {
		where = where + " AND target_sector = ?"
		args = append(args, f.Sector)
	}
	if f.SeverityMin > 0 {
		where = where + " AND severity >= ?"
		args = append(args, f.SeverityMin)
	}
	if f.Query != "" {
		where = where + " AND (victim LIKE ? OR domain LIKE ? OR ransomware_group LIKE ?)"
		q := "%" + f.Query + "%"
		args = append(args, q, q, q)
	}

	var toplam int
	err := db.QueryRow("SELECT COUNT(*) FROM victims"+where, args...).Scan(&toplam)
	if err != nil {
		return nil, 0, err
	}

	if f.Limit <= 0 {
		f.Limit = 50
	}
	args = append(args, f.Limit, f.Offset)
	rows, err := db.Query("SELECT "+victimkolonlar+" FROM victims"+where+
		" ORDER BY date DESC, id DESC LIMIT ? OFFSET ?", args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	sonuc := victimoku(rows)
	return sonuc, toplam, rows.Err()
}

func (db *DB) AllVictims() ([]model.Victim, error) {
	rows, err := db.Query("SELECT " + victimkolonlar + " FROM victims ORDER BY id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return victimoku(rows), rows.Err()
}

type IOCFilter struct {
	Type   string
	Group  string
	Query  string
	Limit  int
	Offset int
}

func iocoku(rows *sql.Rows) []model.IOC {
	sonuc := []model.IOC{}
	for rows.Next() {
		var m model.IOC
		err := rows.Scan(&m.Value, &m.Type, &m.Group, &m.MalwareFamily, &m.Confidence, &m.FirstSeen, &m.Source)
		if err != nil {
			continue
		}
		sonuc = append(sonuc, m)
	}
	return sonuc
}

func (db *DB) IOCList(f IOCFilter) ([]model.IOC, int, error) {
	where := " WHERE 1=1"
	args := []any{}
	if f.Type != "" {
		where = where + " AND type = ?"
		args = append(args, f.Type)
	}
	if f.Group != "" {
		where = where + " AND ransomware_group = ?"
		args = append(args, f.Group)
	}
	if f.Query != "" {
		where = where + " AND (value LIKE ? OR malware_family LIKE ? OR ransomware_group LIKE ?)"
		q := "%" + f.Query + "%"
		args = append(args, q, q, q)
	}

	var toplam int
	err := db.QueryRow("SELECT COUNT(*) FROM iocs"+where, args...).Scan(&toplam)
	if err != nil {
		return nil, 0, err
	}

	if f.Limit <= 0 {
		f.Limit = 50
	}
	args = append(args, f.Limit, f.Offset)
	rows, err := db.Query("SELECT value, type, ransomware_group, malware_family, confidence, first_seen, source FROM iocs"+where+
		" ORDER BY (first_seen = '') ASC, first_seen DESC, value LIMIT ? OFFSET ?", args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	return iocoku(rows), toplam, rows.Err()
}

func (db *DB) IOCGroups() ([]GroupStat, error) {
	rows, err := db.Query("SELECT ransomware_group, COUNT(*) c FROM iocs GROUP BY ransomware_group ORDER BY c DESC")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sonuc := []GroupStat{}
	for rows.Next() {
		var g GroupStat
		err = rows.Scan(&g.Group, &g.Count)
		if err != nil {
			return nil, err
		}
		sonuc = append(sonuc, g)
	}
	return sonuc, rows.Err()
}

type IOCResult struct {
	Query    string         `json:"query"`
	Matches  []model.IOC    `json:"matches"`
	Groups   []string       `json:"groups"`
	Victims  []model.Victim `json:"victims"`
	Severity struct {
		Count int     `json:"count"`
		Avg   float64 `json:"avg"`
		Min   int     `json:"min"`
		Max   int     `json:"max"`
	} `json:"severity"`
}

func (db *DB) IOCSearch(q string) (IOCResult, error) {
	q = strings.TrimSpace(q)
	var sonuc IOCResult
	sonuc.Query = q
	sonuc.Matches = []model.IOC{}
	sonuc.Groups = []string{}
	sonuc.Victims = []model.Victim{}
	if q == "" {
		return sonuc, nil
	}

	rows, err := db.Query(`SELECT value, type, ransomware_group, malware_family, confidence, first_seen, source
		FROM iocs WHERE value = ? OR value LIKE ? ORDER BY confidence DESC LIMIT 200`, q, q+"%")
	if err != nil {
		return sonuc, err
	}
	gruplar := map[string]bool{}
	for rows.Next() {
		var m model.IOC
		err = rows.Scan(&m.Value, &m.Type, &m.Group, &m.MalwareFamily, &m.Confidence, &m.FirstSeen, &m.Source)
		if err != nil {
			rows.Close()
			return sonuc, err
		}
		sonuc.Matches = append(sonuc.Matches, m)
		if m.Group != "" {
			gruplar[m.Group] = true
		}
	}
	rows.Close()

	vrows, err := db.Query("SELECT DISTINCT ransomware_group FROM victims WHERE ioc_ip = ? OR ioc_hash = ?", q, q)
	if err == nil {
		for vrows.Next() {
			var g string
			if vrows.Scan(&g) == nil && g != "" {
				gruplar[g] = true
			}
		}
		vrows.Close()
	}

	if len(gruplar) == 0 {
		return sonuc, nil
	}
	isaretler := []string{}
	args := []any{}
	for g := range gruplar {
		sonuc.Groups = append(sonuc.Groups, g)
		isaretler = append(isaretler, "?")
		args = append(args, g)
	}
	liste := strings.Join(isaretler, ",")

	vr, err := db.Query("SELECT "+victimkolonlar+" FROM victims WHERE ransomware_group IN ("+liste+
		") ORDER BY date DESC LIMIT 100", args...)
	if err != nil {
		return sonuc, err
	}
	sonuc.Victims = victimoku(vr)
	vr.Close()

	db.QueryRow("SELECT COUNT(*), COALESCE(AVG(severity),0), COALESCE(MIN(severity),0), COALESCE(MAX(severity),0) FROM victims WHERE ransomware_group IN ("+liste+")", args...).
		Scan(&sonuc.Severity.Count, &sonuc.Severity.Avg, &sonuc.Severity.Min, &sonuc.Severity.Max)
	return sonuc, nil
}

func (db *DB) SaveAll(victims []model.Victim, iocs []model.IOC, meta map[string]string) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec("DELETE FROM victims")
	if err != nil {
		return err
	}
	_, err = tx.Exec("DELETE FROM iocs")
	if err != nil {
		return err
	}
	_, err = tx.Exec("DELETE FROM meta")
	if err != nil {
		return err
	}

	st1, err := tx.Prepare(`INSERT INTO victims
		(date, ransomware_group, country, country_name, target_sector, attack_vector,
		 technique_id, technique, severity, ioc_ip, ioc_hash, victim, description, domain, claim_url, source_url)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer st1.Close()
	for _, v := range victims {
		_, err = st1.Exec(v.Date, v.Group, v.Country, v.CountryName, v.Sector, v.AttackVector,
			v.TechniqueID, v.TechniqueName, v.Severity, v.IOCIP, v.IOCHash, v.Org, v.Description,
			v.Domain, v.ClaimURL, v.SourceURL)
		if err != nil {
			return err
		}
	}

	st2, err := tx.Prepare(`INSERT INTO iocs
		(value, type, ransomware_group, malware_family, confidence, first_seen, source)
		VALUES (?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer st2.Close()
	for _, ioc := range iocs {
		_, err = st2.Exec(ioc.Value, ioc.Type, ioc.Group, ioc.MalwareFamily,
			ioc.Confidence, ioc.FirstSeen, ioc.Source)
		if err != nil {
			return err
		}
	}

	st3, err := tx.Prepare("INSERT INTO meta (key, value) VALUES (?, ?)")
	if err != nil {
		return err
	}
	defer st3.Close()
	for k, v := range meta {
		_, err = st3.Exec(k, v)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}
