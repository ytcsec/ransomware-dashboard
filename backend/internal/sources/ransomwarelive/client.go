package ransomwarelive

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"ransomware-cti/internal/httpx"
	"ransomware-cti/internal/model"
	"ransomware-cti/internal/util"
)

type Client struct {
	base string
	http *httpx.Client
}

func New(base string, h *httpx.Client) *Client {
	c := &Client{}
	c.base = strings.TrimRight(base, "/")
	c.http = h
	return c
}

type victimjson struct {
	Victim      string `json:"victim"`
	Group       string `json:"group"`
	Country     string `json:"country"`
	Activity    string `json:"activity"`
	AttackDate  string `json:"attackdate"`
	Discovered  string `json:"discovered"`
	Description string `json:"description"`
	ClaimURL    string `json:"claim_url"`
	Domain      string `json:"domain"`
	URL         string `json:"url"`
}

func (c *Client) GetMonth(ctx context.Context, yil int, ay int) ([]model.Victim, error) {
	adres := fmt.Sprintf("%s/victims/%d/%02d", c.base, yil, ay)
	status, data, err := c.http.Do(ctx, "GET", adres, nil, nil)
	if err != nil {
		return nil, err
	}
	if status != 200 {
		return nil, fmt.Errorf("victims %d/%02d: http %d", yil, ay, status)
	}
	var liste []victimjson
	err = json.Unmarshal(data, &liste)
	if err != nil {
		return nil, fmt.Errorf("victims %d/%02d okunamadi: %w", yil, ay, err)
	}
	sonuc := []model.Victim{}
	for _, r := range liste {
		grup := strings.TrimSpace(r.Group)
		if grup == "" {
			continue
		}
		var v model.Victim
		v.Date = util.PickDate(r.AttackDate, r.Discovered)
		v.Group = grup
		v.Country = strings.ToUpper(strings.TrimSpace(r.Country))
		v.Sector = strings.TrimSpace(r.Activity)
		v.Org = strings.TrimSpace(r.Victim)
		v.Description = strings.TrimSpace(r.Description)
		v.Domain = strings.TrimSpace(r.Domain)
		v.ClaimURL = strings.TrimSpace(r.ClaimURL)
		v.SourceURL = strings.TrimSpace(r.URL)
		sonuc = append(sonuc, v)
	}
	return sonuc, nil
}

type techjson struct {
	TechniqueID   string `json:"technique_id"`
	TechniqueName string `json:"technique_name"`
}

type ttpjson struct {
	TacticID   string     `json:"tactic_id"`
	TacticName string     `json:"tactic_name"`
	Techniques []techjson `json:"techniques"`
}

type groupjson struct {
	Name string    `json:"name"`
	TTPs []ttpjson `json:"ttps"`
}

func (c *Client) GetGroup(ctx context.Context, isim string) (model.GroupProfile, error) {
	adres := fmt.Sprintf("%s/group/%s", c.base, url.PathEscape(isim))
	status, data, err := c.http.Do(ctx, "GET", adres, nil, nil)
	if err != nil {
		return model.GroupProfile{}, err
	}
	if status != 200 {
		return model.GroupProfile{}, fmt.Errorf("group %s: http %d", isim, status)
	}
	var g groupjson
	err = json.Unmarshal(data, &g)
	if err != nil {
		return model.GroupProfile{}, fmt.Errorf("group %s okunamadi: %w", isim, err)
	}
	p := model.GroupProfile{Name: isim}
	for _, t := range g.TTPs {
		for _, tek := range t.Techniques {
			id := strings.TrimSpace(tek.TechniqueID)
			if id == "" {
				continue
			}
			var yeni model.Technique
			yeni.TacticID = t.TacticID
			yeni.TacticName = t.TacticName
			yeni.TechniqueID = id
			yeni.TechniqueName = strings.TrimSpace(tek.TechniqueName)
			p.Techniques = append(p.Techniques, yeni)
		}
	}
	return p, nil
}
