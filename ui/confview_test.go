package ui

import (
	"testing"
	"time"
)

func TestParseHandshakeElapsed(t *testing.T) {
	tests := []struct {
		input string
		want  time.Duration
	}{
		{"", 0},
		{"never", 0},
		{"Now", 1 * time.Second},
		{"just now", 1 * time.Second},
		{"3 minutes ago", 3 * time.Minute},
		{"a minute ago", 1 * time.Minute},
		{"an hour ago", 1 * time.Hour},
		{"2 hours ago", 2 * time.Hour},
		{"5 seconds ago", 5 * time.Second},
		{"3 小时前", 3 * time.Hour},
		{"3小时", 3 * time.Hour},
		{"10分钟", 10 * time.Minute},
	}

	for _, tc := range tests {
		got := parseHandshakeElapsed(tc.input)
		if got != tc.want {
			t.Errorf("parseHandshakeElapsed(%q) = %v; want %v", tc.input, got, tc.want)
		}
	}
}
