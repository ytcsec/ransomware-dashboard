package util

import (
	"strings"
	"time"
)

var formats = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05.999999999",
	"2006-01-02 15:04:05.999999",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05",
	"2006-01-02",
}

func ParseDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for i := 0; i < len(formats); i++ {
		t, err := time.Parse(formats[i], s)
		if err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func ToDate(s string) string {
	t, ok := ParseDate(s)
	if ok {
		return t.Format("2006-01-02")
	}
	return ""
}

func PickDate(first string, second string) string {
	d := ToDate(first)
	if d != "" {
		return d
	}
	return ToDate(second)
}
