#!/bin/bash

systemctl stop netfoil-time.socket --quiet
systemctl stop netfoil-time.service --quiet

set -e

sleep .2
cp systemd/netfoil-time.socket /usr/lib/systemd/system/netfoil-time.socket
cp systemd/netfoil-time.service /usr/lib/systemd/system/netfoil-time.service
cp systemd/netfoil_time.slice /usr/lib/systemd/system/netfoil_time.slice

cp netfoil-time /usr/sbin/netfoil-time
systemctl daemon-reload
systemctl start netfoil-time.socket
systemctl start netfoil-time.service

systemctl enable netfoil-time.service
