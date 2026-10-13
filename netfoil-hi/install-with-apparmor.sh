#!/bin/bash

systemctl stop netfoil-hi.socket --quiet
systemctl stop netfoil-hi.service --quiet

set -e

# AppArmor
cp apparmor/netfoil-hi /etc/apparmor.d/netfoil-hi
apparmor_parser -r /etc/apparmor.d/netfoil-hi

sleep .2
cp systemd/netfoil-hi.socket /usr/lib/systemd/system/netfoil-hi.socket
cp systemd/netfoil-hi.service /usr/lib/systemd/system/netfoil-hi.service
cp systemd/netfoil_hi.slice /usr/lib/systemd/system/netfoil_hi.slice

cp netfoil-hi /usr/sbin/netfoil-hi
systemctl daemon-reload
systemctl start netfoil-hi.socket
systemctl start netfoil-hi.service

systemctl enable netfoil-hi.service
