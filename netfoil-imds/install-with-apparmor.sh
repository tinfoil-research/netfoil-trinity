#!/bin/bash

instance="$1"
if [[ -z "$instance" ]]; then
	echo "systemd instance must be specified, e.g. 'default'"
	exit 1
fi

echo "instance $instance"

systemctl stop "netfoil-imds-$instance.socket" --quiet
systemctl stop "netfoil-imds@$instance.service" --quiet

set -e

# AppArmor
cp apparmor/netfoil-imds /etc/apparmor.d/netfoil-imds
apparmor_parser -r /etc/apparmor.d/netfoil-imds

sleep .2
cp "systemd/netfoil-imds@.service" "/usr/lib/systemd/system/netfoil-imds@.service"
cp "systemd/netfoil-imds-$instance.socket" "/usr/lib/systemd/system/netfoil-imds-$instance.socket"
cp "systemd/netfoil_$instance-imds.slice" "/usr/lib/systemd/system/netfoil_$instance-imds.slice"

cp netfoil-imds /usr/sbin/netfoil-imds
systemctl daemon-reload
systemctl start "netfoil-imds-$instance.socket"
systemctl start "netfoil-imds@$instance.service"

systemctl enable "netfoil-imds@$instance.service"
