#!/bin/bash

instance="$1"
if [[ -z "$instance" ]]; then
	echo "systemd instance must be specified, e.g. 'default'"
	exit 1
fi

echo "instance $instance"

cp "netfoil_$instance.slice" "/usr/lib/systemd/system/netfoil_$instance.slice"
systemctl daemon-reload
