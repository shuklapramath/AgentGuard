#!/bin/bash
# Root: mount securityfs if lsm is unreadable, then drop to ubuntu.
# Mount failure must not abort (CI docker run is not privileged).
set -u
LSM=/sys/kernel/security/lsm
if [ ! -r "$LSM" ]; then
	mkdir -p /sys/kernel/security
	mount -t securityfs securityfs /sys/kernel/security 2>/dev/null || true
fi

if [ $# -eq 0 ]; then
	exec runuser -u ubuntu -- bash
fi
exec runuser -u ubuntu -- "$@"
