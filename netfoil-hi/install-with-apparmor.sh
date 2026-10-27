#!/bin/bash

instance="$1"
if [[ -z "$instance" ]]; then
	echo "systemd instance must be specified, e.g. 'default'"
	exit 1
fi

echo "instance $instance"

systemctl stop "netfoil-hi-$instance.socket" --quiet
systemctl stop "netfoil-hi@$instance.service" --quiet

set -e

# AppArmor
cp apparmor/netfoil-hi /etc/apparmor.d/netfoil-hi
apparmor_parser -r /etc/apparmor.d/netfoil-hi

sleep .2
cp "systemd/netfoil-hi@.service" "/usr/lib/systemd/system/netfoil-hi@.service"
cp "systemd/netfoil-hi-$instance.socket" "/usr/lib/systemd/system/netfoil-hi-$instance.socket"
cp "systemd/netfoil_$instance-hi.slice" "/usr/lib/systemd/system/netfoil_$instance-hi.slice"

cp -f netfoil-hi /usr/sbin/netfoil-hi
systemctl daemon-reload
systemctl start "netfoil-hi-$instance.socket"
systemctl start "netfoil-hi@$instance.service"

systemctl enable "netfoil-hi@$instance.service"
