package ingest

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"ransomware-cti/internal/config"
	"ransomware-cti/internal/enrich"
	"ransomware-cti/internal/httpx"
	"ransomware-cti/internal/model"
	"ransomware-cti/internal/sources/abusech"
	"ransomware-cti/internal/sources/ransomwarelive"
	"ransomware-cti/internal/store"
	"ransomware-cti/internal/util"
)

type Stats struct {
	Victims     int
	Groups      int
	IOCs        int
	AvgSeverity float64
	IOCMode     string
	GeneratedAt string
}

var kilit sync.Mutex

func Run(ctx context.Context, cfg config.Config) (Stats, error) {
	kilit.Lock()
	defer kilit.Unlock()

	var stats Stats
	if !cfg.Refresh {
		_, err := os.Stat(cfg.DbPath)
		if err == nil {
			log.Printf("veritabani zaten var (%s), atlaniyor. Yeniden cekmek icin REFRESH=true.", cfg.DbPath)
			return stats, nil
		}
	}
	err := os.MkdirAll(cfg.DataDir, 0755)
	if err != nil {
		return stats, err
	}
	cachedir := filepath.Join(cfg.DataDir, "cache")
	os.MkdirAll(cachedir, 0755)

	rl := ransomwarelive.New(cfg.RansomBase, httpx.New(cfg.Throttle, cfg.Retry, cfg.Agent))

	aylar := aylistesi(cfg.From)
	log.Printf("ransomware.live: %s -> simdi (%d ay) cekiliyor", cfg.From, len(aylar))
	taban := cfg.From + "-01"
	victims := []model.Victim{}
	gorulen := map[string]bool{}
	for _, ay := range aylar {
		liste, err := rl.GetMonth(ctx, ay.yil, ay.ay)
		if err != nil {
			log.Printf("  %d/%02d atlandi: %v", ay.yil, ay.ay, err)
			continue
		}
		eklenen := 0
		for _, v := range liste {
			if v.Date == "" || v.Date < taban {
				continue
			}
			anahtar := v.SourceURL
			if anahtar == "" {
				anahtar = v.Group + "|" + v.Org + "|" + v.Date
			}
			if gorulen[anahtar] {
				continue
			}
			gorulen[anahtar] = true
			victims = append(victims, v)
			eklenen++
		}
		log.Printf("  %d/%02d: %d kayit (+%d benzersiz)", ay.yil, ay.ay, len(liste), eklenen)
	}
	if len(victims) == 0 {
		return stats, fmt.Errorf("hic kurban kaydi cekilemedi")
	}
	log.Printf("toplam %d benzersiz kurban", len(victims))

	gruplar := grupisimleri(victims)
	log.Printf("%d benzersiz grup, MITRE profilleri (cache: %s)", len(gruplar), cachedir)
	profiller := map[string]model.GroupProfile{}
	for i, g := range gruplar {
		p, err := profilgetir(ctx, rl, cachedir, g)
		if err != nil {
			p = model.GroupProfile{Name: g}
		}
		p.HasImpact = enrich.HasImpact(p.Techniques)
		profiller[g] = p
		if (i+1)%25 == 0 {
			log.Printf("  ...%d/%d grup profili", i+1, len(gruplar))
		}
	}

	ab := abusech.New(cfg.AbuseKey, httpx.New(500, cfg.Retry, cfg.Agent))
	iocmode := ""
	var indeks map[string][]model.IOC
	if ab.Enabled() {
		iocmode = "real (abuse.ch API)"
	} else {
		istenen := map[string]bool{}
		for _, g := range gruplar {
			for _, fam := range abusech.FamilyNames(g) {
				istenen[fam] = true
			}
		}
		log.Printf("IOC: ThreatFox tam export indiriliyor (key'siz gercek veri)...")
		idx, err := ab.LoadExport(ctx, cachedir, cfg.Refresh, istenen)
		if err != nil {
			log.Printf("  export alinamadi (%v); sentetik IOC'a dusuluyor", err)
			iocmode = "synthetic (export erisilemedi)"
		} else {
			indeks = idx
			iocmode = "real (abuse.ch ThreatFox)"
		}
	}
	log.Printf("IOC modu: %s", iocmode)

	grupiocs := map[string][]model.IOC{}
	tumiocs := []model.IOC{}
	eslesen := 0
	for _, g := range gruplar {
		var iocs []model.IOC
		if ab.Enabled() {
			iocs = iocgetir(ctx, ab, cachedir, g, cfg.Refresh, cfg.IocLimit)
		} else if indeks != nil {
			iocs = abusech.IOCsFromIndex(g, indeks, cfg.IocLimit)
		} else {
			iocs = enrich.SyntheticIOCs(g, 4)
		}
		if len(iocs) > 0 {
			eslesen++
		}
		grupiocs[g] = iocs
		tumiocs = append(tumiocs, iocs...)
	}
	log.Printf("toplam %d IOC (%d/%d grup eslesti)", len(tumiocs), eslesen, len(gruplar))

	sayilar := map[string]int{}
	for _, v := range victims {
		sayilar[v.Group]++
	}
	enbuyuk := 1
	for _, c := range sayilar {
		if c > enbuyuk {
			enbuyuk = c
		}
	}
	sontarih := songun(victims)

	sira := map[string]int{}
	for i := range victims {
		v := &victims[i]
		v.CountryName = enrich.CountryEN(v.Country)
		v.Sector = enrich.SectorLabel(v.Sector)
		p := profiller[v.Group]
		idx := sira[v.Group]
		sira[v.Group]++

		v.AttackVector = enrich.AttackVector(p, idx)
		teknik := enrich.PrimaryTechnique(p, idx)
		v.TechniqueID = teknik.TechniqueID
		v.TechniqueName = teknik.TechniqueName

		ipler, hashler := iocayir(grupiocs[v.Group])
		if len(ipler) > 0 {
			v.IOCIP = ipler[idx%len(ipler)]
		}
		if len(hashler) > 0 {
			v.IOCHash = hashler[idx%len(hashler)]
		}

		t, _ := util.ParseDate(v.Date)
		v.Severity = enrich.ComputeSeverity(enrich.SeverityInput{
			SectorScore:    enrich.SectorScore(v.Sector),
			GroupScore:     enrich.GroupScore(sayilar[v.Group], enbuyuk),
			ImpactScore:    enrich.ImpactScore(p),
			FreshnessScore: enrich.FreshnessScore(t, sontarih),
			IOCScore:       enrich.IOCScore(len(grupiocs[v.Group]) > 0),
		})
	}

	sonay := aylar[len(aylar)-1]
	zaman := time.Now().UTC().Format(time.RFC3339)
	meta := map[string]string{}
	meta["generated_at"] = zaman
	meta["victim_count"] = strconv.Itoa(len(victims))
	meta["ioc_count"] = strconv.Itoa(len(tumiocs))
	meta["group_count"] = strconv.Itoa(len(gruplar))
	meta["window_from"] = cfg.From
	meta["window_to"] = fmt.Sprintf("%04d-%02d", sonay.yil, sonay.ay)
	meta["ioc_mode"] = iocmode
	meta["avg_severity"] = fmt.Sprintf("%.2f", ortalama(victims))
	meta["sources"] = "ransomware.live v2; abuse.ch ThreatFox & MalwareBazaar; MITRE ATT&CK"

	db, err := store.Open(cfg.DbPath)
	if err != nil {
		return stats, err
	}
	defer db.Close()
	err = db.Migrate()
	if err != nil {
		return stats, err
	}
	err = db.SaveAll(victims, tumiocs, meta)
	if err != nil {
		return stats, err
	}
	log.Printf("SQLite yazildi: %s", cfg.DbPath)

	err = csvyaz(filepath.Join(cfg.DataDir, "dataset.csv"), victims)
	if err != nil {
		return stats, err
	}
	err = jsonyaz(filepath.Join(cfg.DataDir, "dataset.json"), victims)
	if err != nil {
		return stats, err
	}

	stats.Victims = len(victims)
	stats.Groups = len(gruplar)
	stats.IOCs = len(tumiocs)
	stats.AvgSeverity = ortalama(victims)
	stats.IOCMode = iocmode
	stats.GeneratedAt = zaman
	log.Printf("OZET: %d kurban | %d grup | %d IOC | ort. severity %.2f | %s",
		stats.Victims, stats.Groups, stats.IOCs, stats.AvgSeverity, stats.IOCMode)
	return stats, nil
}

func RunIocs(ctx context.Context, cfg config.Config) (Stats, error) {
	kilit.Lock()
	defer kilit.Unlock()
	var stats Stats

	cachedir := filepath.Join(cfg.DataDir, "cache")
	db, err := store.Open(cfg.DbPath)
	if err != nil {
		return stats, err
	}
	defer db.Close()

	victims, err := db.AllVictims()
	if err != nil {
		return stats, err
	}
	if len(victims) == 0 {
		return stats, fmt.Errorf("DB'de kurban yok; once tam pipeline calistirin")
	}
	gruplar := grupisimleri(victims)
	log.Printf("IOC yeniden cekiliyor: %d kurban / %d grup (kurban DB'den, sadece IOC yenileniyor)", len(victims), len(gruplar))

	ab := abusech.New(cfg.AbuseKey, httpx.New(500, cfg.Retry, cfg.Agent))
	iocmode := ""
	var indeks map[string][]model.IOC
	if ab.Enabled() {
		iocmode = "real (abuse.ch API)"
	} else {
		istenen := map[string]bool{}
		for _, g := range gruplar {
			for _, fam := range abusech.FamilyNames(g) {
				istenen[fam] = true
			}
		}
		idx, err := ab.LoadExport(ctx, cachedir, cfg.Refresh, istenen)
		if err != nil {
			return stats, fmt.Errorf("ThreatFox export alinamadi: %w", err)
		}
		indeks = idx
		iocmode = "real (abuse.ch ThreatFox)"
	}

	grupiocs := map[string][]model.IOC{}
	tumiocs := []model.IOC{}
	for _, g := range gruplar {
		var iocs []model.IOC
		if ab.Enabled() {
			iocs = iocgetir(ctx, ab, cachedir, g, true, cfg.IocLimit)
		} else {
			iocs = abusech.IOCsFromIndex(g, indeks, cfg.IocLimit)
		}
		grupiocs[g] = iocs
		tumiocs = append(tumiocs, iocs...)
	}

	sira := map[string]int{}
	for i := range victims {
		v := &victims[i]
		v.IOCIP = ""
		v.IOCHash = ""
		ipler, hashler := iocayir(grupiocs[v.Group])
		idx := sira[v.Group]
		sira[v.Group]++
		if len(ipler) > 0 {
			v.IOCIP = ipler[idx%len(ipler)]
		}
		if len(hashler) > 0 {
			v.IOCHash = hashler[idx%len(hashler)]
		}
	}

	meta, _ := db.Meta()
	if meta == nil {
		meta = map[string]string{}
	}
	meta["ioc_count"] = strconv.Itoa(len(tumiocs))
	meta["ioc_mode"] = iocmode
	meta["generated_at"] = time.Now().UTC().Format(time.RFC3339)
	err = db.SaveAll(victims, tumiocs, meta)
	if err != nil {
		return stats, err
	}
	err = csvyaz(filepath.Join(cfg.DataDir, "dataset.csv"), victims)
	if err != nil {
		return stats, err
	}
	err = jsonyaz(filepath.Join(cfg.DataDir, "dataset.json"), victims)
	if err != nil {
		return stats, err
	}

	stats.Victims = len(victims)
	stats.Groups = len(gruplar)
	stats.IOCs = len(tumiocs)
	stats.IOCMode = iocmode
	stats.GeneratedAt = meta["generated_at"]
	log.Printf("IOC yenileme bitti: %d IOC | %s", stats.IOCs, iocmode)
	return stats, nil
}

type aybilgi struct {
	yil int
	ay  int
}

func aylistesi(from string) []aybilgi {
	t, ok := util.ParseDate(from + "-01")
	if !ok {
		t = time.Date(2024, 7, 1, 0, 0, 0, 0, time.UTC)
	}
	simdi := time.Now().UTC()
	yil := t.Year()
	ay := int(t.Month())
	sonuc := []aybilgi{}
	for {
		sonuc = append(sonuc, aybilgi{yil, ay})
		if yil == simdi.Year() && ay == int(simdi.Month()) {
			break
		}
		ay++
		if ay > 12 {
			ay = 1
			yil++
		}
		if yil > simdi.Year()+1 {
			break
		}
	}
	return sonuc
}

func grupisimleri(victims []model.Victim) []string {
	gorulen := map[string]bool{}
	sonuc := []string{}
	for _, v := range victims {
		if !gorulen[v.Group] {
			gorulen[v.Group] = true
			sonuc = append(sonuc, v.Group)
		}
	}
	return sonuc
}

func profilgetir(ctx context.Context, rl *ransomwarelive.Client, cachedir string, g string) (model.GroupProfile, error) {
	dosya := filepath.Join(cachedir, "group_"+temizisim(g)+".json")
	data, err := os.ReadFile(dosya)
	if err == nil {
		var p model.GroupProfile
		if json.Unmarshal(data, &p) == nil {
			return p, nil
		}
	}
	p, err := rl.GetGroup(ctx, g)
	if err != nil {
		return model.GroupProfile{Name: g}, err
	}
	data, err = json.Marshal(p)
	if err == nil {
		os.WriteFile(dosya, data, 0644)
	}
	return p, nil
}

func iocgetir(ctx context.Context, ab *abusech.Client, cachedir string, g string, refresh bool, limit int) []model.IOC {
	dosya := filepath.Join(cachedir, "ioc_"+temizisim(g)+".json")
	if !refresh {
		data, err := os.ReadFile(dosya)
		if err == nil {
			var iocs []model.IOC
			if json.Unmarshal(data, &iocs) == nil {
				return iocs
			}
		}
	}
	iocs, _ := ab.GetIOCs(ctx, g, limit)
	data, err := json.Marshal(iocs)
	if err == nil {
		os.WriteFile(dosya, data, 0644)
	}
	return iocs
}

func iocayir(iocs []model.IOC) ([]string, []string) {
	ipler := []string{}
	hashler := []string{}
	for _, ioc := range iocs {
		if ioc.Type == "ip" {
			ipler = append(ipler, ioc.Value)
		}
		if ioc.Type == "hash" {
			hashler = append(hashler, ioc.Value)
		}
	}
	return ipler, hashler
}

func songun(victims []model.Victim) time.Time {
	var enson time.Time
	for _, v := range victims {
		t, ok := util.ParseDate(v.Date)
		if ok && t.After(enson) {
			enson = t
		}
	}
	if enson.IsZero() {
		return time.Now().UTC()
	}
	return enson
}

func ortalama(victims []model.Victim) float64 {
	if len(victims) == 0 {
		return 0
	}
	toplam := 0
	for _, v := range victims {
		toplam = toplam + v.Severity
	}
	return float64(toplam) / float64(len(victims))
}

func temizisim(s string) string {
	sonuc := ""
	for _, harf := range s {
		if (harf >= 'a' && harf <= 'z') || (harf >= 'A' && harf <= 'Z') || (harf >= '0' && harf <= '9') || harf == '-' || harf == '_' {
			sonuc = sonuc + string(harf)
		} else {
			sonuc = sonuc + "_"
		}
	}
	return sonuc
}

type satir struct {
	Date         string `json:"date"`
	Group        string `json:"ransomware_group"`
	Country      string `json:"country"`
	Sector       string `json:"target_sector"`
	AttackVector string `json:"attack_vector"`
	Technique    string `json:"technique"`
	Severity     int    `json:"severity"`
	IOCIP        string `json:"ioc_ip"`
	IOCHash      string `json:"ioc_hash"`
}

func csvyaz(dosya string, victims []model.Victim) error {
	f, err := os.Create(dosya)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	err = w.Write([]string{"date", "ransomware_group", "country", "target_sector", "attack_vector", "technique", "severity", "ioc_ip", "ioc_hash"})
	if err != nil {
		return err
	}
	for _, v := range victims {
		err = w.Write([]string{v.Date, v.Group, v.Country, v.Sector, v.AttackVector, v.TechniqueName, strconv.Itoa(v.Severity), v.IOCIP, v.IOCHash})
		if err != nil {
			return err
		}
	}
	return w.Error()
}

func jsonyaz(dosya string, victims []model.Victim) error {
	satirlar := []satir{}
	for _, v := range victims {
		var s satir
		s.Date = v.Date
		s.Group = v.Group
		s.Country = v.Country
		s.Sector = v.Sector
		s.AttackVector = v.AttackVector
		s.Technique = v.TechniqueName
		s.Severity = v.Severity
		s.IOCIP = v.IOCIP
		s.IOCHash = v.IOCHash
		satirlar = append(satirlar, s)
	}
	data, err := json.MarshalIndent(satirlar, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(dosya, data, 0644)
}
