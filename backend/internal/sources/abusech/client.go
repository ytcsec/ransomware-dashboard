package abusech

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"ransomware-cti/internal/httpx"
	"ransomware-cti/internal/model"
)

var threatfoxurl = "https://threatfox-api.abuse.ch/api/v1/"
var bazaarurl = "https://mb-api.abuse.ch/api/v1/"
var exporturl = "https://threatfox.abuse.ch/export/json/full/"

type Client struct {
	key  string
	http *httpx.Client
}

func New(key string, h *httpx.Client) *Client {
	c := &Client{}
	c.key = strings.TrimSpace(key)
	c.http = h
	return c
}

func (c *Client) Enabled() bool {
	if c.key != "" {
		return true
	}
	return false
}

type isimler struct {
	tf string
	mb string
}

var families = map[string]isimler{
	"lockbit":     {"win.lockbit", "LockBit"},
	"lockbit3":    {"win.lockbit", "LockBit"},
	"alphv":       {"win.blackcat", "BlackCat"},
	"blackcat":    {"win.blackcat", "BlackCat"},
	"clop":        {"win.clop", "Clop"},
	"cl0p":        {"win.clop", "Clop"},
	"akira":       {"win.akira", "Akira"},
	"play":        {"win.play", "Play"},
	"playcrypt":   {"win.play", "Play"},
	"blackbasta":  {"win.black_basta", "BlackBasta"},
	"bianlian":    {"win.bianlian", "BianLian"},
	"royal":       {"win.royal_ransom", "Royal"},
	"rhysida":     {"win.rhysida", "Rhysida"},
	"medusa":      {"win.medusa", "Medusa"},
	"blacksuit":   {"win.blacksuit", "BlackSuit"},
	"qilin":       {"win.qilin", "Qilin"},
	"agenda":      {"win.qilin", "Qilin"},
	"hunters":     {"win.hunters_international", "HuntersInternational"},
	"8base":       {"win.phobos", "Phobos"},
	"phobos":      {"win.phobos", "Phobos"},
	"ransomhub":   {"win.ransomhub", "RansomHub"},
	"cactus":      {"win.cactus", "Cactus"},
	"incransom":   {"win.inc", "INC"},
	"inc":         {"win.inc", "INC"},
	"dragonforce": {"win.dragonforce", "DragonForce"},
	"safepay":     {"win.safepay", "SafePay"},
	"trigona":     {"win.trigona", "Trigona"},
	"darkside":    {"win.darkside", "DarkSide"},
	"revil":       {"win.revil", "REvil"},
	"conti":       {"win.conti", "Conti"},
}

func fixname(g string) string {
	g = strings.ToLower(strings.TrimSpace(g))
	g = strings.ReplaceAll(g, " ", "")
	g = strings.ReplaceAll(g, "-", "")
	g = strings.ReplaceAll(g, "_", "")
	return g
}

func bulfamily(grup string) (isimler, bool) {
	n := fixname(grup)
	f, ok := families[n]
	if ok {
		return f, true
	}
	n2 := strings.TrimRight(n, "0123456789")
	f, ok = families[n2]
	if ok {
		return f, true
	}
	return isimler{}, false
}

func ioctipi(tip string, deger string) (string, string) {
	if tip == "ip:port" {
		i := strings.LastIndex(deger, ":")
		if i > 0 {
			return "ip", deger[:i]
		}
		return "ip", deger
	}
	if tip == "domain" {
		return "domain", deger
	}
	if tip == "url" {
		return "url", deger
	}
	if tip == "sha256_hash" || tip == "md5_hash" || tip == "sha1_hash" {
		return "hash", deger
	}
	return "", ""
}

type tfcevap struct {
	QueryStatus string          `json:"query_status"`
	Data        json.RawMessage `json:"data"`
}

type tfkayit struct {
	IOC        string `json:"ioc"`
	IOCType    string `json:"ioc_type"`
	Confidence int    `json:"confidence_level"`
	FirstSeen  string `json:"first_seen"`
}

func (c *Client) threatfox(ctx context.Context, malware string, limit int) []model.IOC {
	body, _ := json.Marshal(map[string]any{"query": "malwareinfo", "malware": malware, "limit": limit})
	headers := map[string]string{"Auth-Key": c.key, "Content-Type": "application/json"}
	status, data, err := c.http.Do(ctx, "POST", threatfoxurl, headers, body)
	if err != nil {
		return nil
	}
	if status != 200 {
		return nil
	}
	var cevap tfcevap
	err = json.Unmarshal(data, &cevap)
	if err != nil {
		return nil
	}
	if cevap.QueryStatus != "ok" {
		return nil
	}
	var kayitlar []tfkayit
	err = json.Unmarshal(cevap.Data, &kayitlar)
	if err != nil {
		return nil
	}
	sonuc := []model.IOC{}
	for _, k := range kayitlar {
		tip, deger := ioctipi(k.IOCType, k.IOC)
		if tip == "" {
			continue
		}
		var ioc model.IOC
		ioc.Value = deger
		ioc.Type = tip
		ioc.MalwareFamily = malware
		ioc.Confidence = k.Confidence
		ioc.FirstSeen = k.FirstSeen
		ioc.Source = "ThreatFox (abuse.ch)"
		sonuc = append(sonuc, ioc)
	}
	return sonuc
}

type mbcevap struct {
	QueryStatus string          `json:"query_status"`
	Data        json.RawMessage `json:"data"`
}

type mbkayit struct {
	SHA256    string `json:"sha256_hash"`
	MD5       string `json:"md5_hash"`
	FirstSeen string `json:"first_seen"`
}

func (c *Client) bazaar(ctx context.Context, imza string, limit int) []model.IOC {
	form := url.Values{}
	form.Set("query", "get_siginfo")
	form.Set("signature", imza)
	form.Set("limit", strconv.Itoa(limit))
	headers := map[string]string{"Auth-Key": c.key, "Content-Type": "application/x-www-form-urlencoded"}
	status, data, err := c.http.Do(ctx, "POST", bazaarurl, headers, []byte(form.Encode()))
	if err != nil {
		return nil
	}
	if status != 200 {
		return nil
	}
	var cevap mbcevap
	err = json.Unmarshal(data, &cevap)
	if err != nil {
		return nil
	}
	if cevap.QueryStatus != "ok" {
		return nil
	}
	var kayitlar []mbkayit
	err = json.Unmarshal(cevap.Data, &kayitlar)
	if err != nil {
		return nil
	}
	sonuc := []model.IOC{}
	for _, k := range kayitlar {
		hash := k.SHA256
		if hash == "" {
			hash = k.MD5
		}
		if hash == "" {
			continue
		}
		var ioc model.IOC
		ioc.Value = hash
		ioc.Type = "hash"
		ioc.MalwareFamily = imza
		ioc.Confidence = 100
		ioc.FirstSeen = k.FirstSeen
		ioc.Source = "MalwareBazaar (abuse.ch)"
		sonuc = append(sonuc, ioc)
	}
	return sonuc
}

func (c *Client) GetIOCs(ctx context.Context, grup string, limit int) ([]model.IOC, bool) {
	f, ok := bulfamily(grup)
	if !ok {
		return nil, false
	}
	hepsi := []model.IOC{}
	tf := c.threatfox(ctx, f.tf, limit)
	hepsi = append(hepsi, tf...)
	mb := c.bazaar(ctx, f.mb, limit)
	hepsi = append(hepsi, mb...)
	for i := 0; i < len(hepsi); i++ {
		hepsi[i].Group = grup
	}
	if len(hepsi) > 0 {
		return hepsi, true
	}
	return hepsi, false
}

type exportkayit struct {
	IOCValue   string `json:"ioc_value"`
	IOCType    string `json:"ioc_type"`
	Malware    string `json:"malware"`
	Confidence int    `json:"confidence_level"`
	FirstSeen  string `json:"first_seen_utc"`
}

func FamilyNames(grup string) []string {
	sonuc := []string{}
	eklendi := map[string]bool{}
	f, ok := bulfamily(grup)
	if ok {
		eklendi[f.tf] = true
		sonuc = append(sonuc, f.tf)
	}
	n := fixname(grup)
	adaylar := []string{"win." + n, "elf." + n, "osx." + n}
	for _, a := range adaylar {
		if !eklendi[a] {
			eklendi[a] = true
			sonuc = append(sonuc, a)
		}
	}
	return sonuc
}

func (c *Client) LoadExport(ctx context.Context, cachedir string, refresh bool, istenen map[string]bool) (map[string][]model.IOC, error) {
	dosya := filepath.Join(cachedir, "threatfox_full.json")
	var data []byte
	if !refresh {
		b, err := os.ReadFile(dosya)
		if err == nil {
			data = b
		}
	}
	if data == nil {
		b, err := c.indirexport(ctx)
		if err != nil {
			return nil, err
		}
		data = b
		os.WriteFile(dosya, data, 0644)
	}

	var ham map[string]json.RawMessage
	err := json.Unmarshal(data, &ham)
	if err != nil {
		return nil, err
	}
	sonuc := map[string][]model.IOC{}
	for _, raw := range ham {
		var kayitlar []exportkayit
		err = json.Unmarshal(raw, &kayitlar)
		if err != nil {
			return nil, err
		}
		for _, k := range kayitlar {
			if istenen != nil && !istenen[k.Malware] {
				continue
			}
			tip, deger := ioctipi(k.IOCType, k.IOCValue)
			if tip != "ip" && tip != "hash" {
				continue
			}
			var ioc model.IOC
			ioc.Value = deger
			ioc.Type = tip
			ioc.MalwareFamily = k.Malware
			ioc.Confidence = k.Confidence
			ioc.FirstSeen = k.FirstSeen
			ioc.Source = "ThreatFox (abuse.ch)"
			sonuc[k.Malware] = append(sonuc[k.Malware], ioc)
		}
	}
	return sonuc, nil
}

func (c *Client) indirexport(ctx context.Context) ([]byte, error) {
	status, body, err := c.http.Do(ctx, "GET", exporturl, nil, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("threatfox export: http %d", status)
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return nil, err
	}
	for _, f := range zr.File {
		if strings.HasSuffix(f.Name, ".json") {
			rc, err := f.Open()
			if err != nil {
				return nil, err
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}
	return nil, fmt.Errorf("zip icinde json yok")
}

func IOCsFromIndex(grup string, indeks map[string][]model.IOC, limit int) []model.IOC {
	sonuc := []model.IOC{}
	eklendi := map[string]bool{}
	for _, fam := range FamilyNames(grup) {
		for _, ioc := range indeks[fam] {
			if eklendi[ioc.Value] {
				continue
			}
			eklendi[ioc.Value] = true
			yeni := ioc
			yeni.Group = grup
			sonuc = append(sonuc, yeni)
			if len(sonuc) >= limit {
				return sonuc
			}
		}
	}
	return sonuc
}
