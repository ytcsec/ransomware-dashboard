package util

import "testing"

func TestToDate(t *testing.T) {
	if ToDate("2026-06-27T18:28:12.666986+00:00") != "2026-06-27" {
		t.Error("uzun tarih formati cozulemedi")
	}
	if ToDate("2026-06-03 00:00:00.000000") != "2026-06-03" {
		t.Error("bosluklu tarih formati cozulemedi")
	}
	if ToDate("2024-01-15") != "2024-01-15" {
		t.Error("kisa tarih formati cozulemedi")
	}
	if ToDate("") != "" {
		t.Error("bos girdi bos donmeli")
	}
	if ToDate("gecersiz") != "" {
		t.Error("gecersiz girdi bos donmeli")
	}
}

func TestPickDate(t *testing.T) {
	if PickDate("2026-06-27T00:00:00Z", "2025-01-01") != "2026-06-27" {
		t.Error("ilk tarih dolu ise o kullanilmali")
	}
	if PickDate("", "2025-01-01") != "2025-01-01" {
		t.Error("ilk tarih bos ise ikinci kullanilmali")
	}
}
