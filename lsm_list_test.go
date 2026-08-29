package main

import "testing"

func TestLSMListHasBPF(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"capability,landlock,yama,apparmor,bpf", true},
		{"bpf", true},
		{" capability , bpf ", true},
		{"capability,landlock,yama,apparmor", false},
		{"", false},
		{"bpfilter", false},
		{"capability,bpf,yama", true},
	}
	for _, c := range cases {
		if got := lsmListHasBPF(c.in); got != c.want {
			t.Errorf("lsmListHasBPF(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
