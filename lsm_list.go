package main

import "strings"

func lsmListHasBPF(contents string) bool {
	for _, tok := range strings.Split(contents, ",") {
		if strings.TrimSpace(tok) == "bpf" {
			return true
		}
	}
	return false
}
