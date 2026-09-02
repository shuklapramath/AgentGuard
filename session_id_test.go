package main

import "testing"

func TestIsHookSessionID(t *testing.T) {
	if !isHookSessionID("01a06345-5769-7ff3-adcf-f9addbe5278c") {
		t.Fatal("Claude/Codex UUID must be accepted")
	}
	if !isHookSessionID("thr_abc12345") {
		t.Fatal("Codex-shaped id must be accepted")
	}
	if isHookSessionID("") {
		t.Fatal("empty must be rejected")
	}
	if isHookSessionID("hello world") {
		t.Fatal("whitespace must be rejected")
	}
	if isHookSessionID("short") {
		t.Fatal("too short must be rejected")
	}
}
