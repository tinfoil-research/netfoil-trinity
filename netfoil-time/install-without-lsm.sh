#!/bin/bash

instance="$1"
if [[ -z "$instance" ]]; then
	echo "systemd instance must be specified, e.g. 'default'"
	exit 1
fi

echo "instance $instance"

systemctl stop "netfoil-time-$instance.socket" --quiet
systemctl stop "netfoil-time@$instance.service" --quiet

set -e

sleep .2
cp "systemd/netfoil-time@.service" "/usr/lib/systemd/system/netfoil-time@.service"
cp "systemd/netfoil-time-$instance.socket" "/usr/lib/systemd/system/netfoil-time-$instance.socket"
cp "systemd/netfoil_$instance-time.slice" "/usr/lib/systemd/system/netfoil_$instance-time.slice"

cp -f netfoil-time /usr/sbin/netfoil-time
systemctl daemon-reload
systemctl start "netfoil-time-$instance.socket"
systemctl start "netfoil-time@$instance.service"

systemctl enable "netfoil-time@$instance.service"
