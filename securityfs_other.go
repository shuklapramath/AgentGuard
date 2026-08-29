//go:build !linux

package main

const securityfsLSMPath = "/sys/kernel/security/lsm"

func lsmFileReadable() bool { return false }

func ensureSecurityfs() error { return nil }
