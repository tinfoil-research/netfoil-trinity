#!/bin/bash

systemctl stop netfoil-imds.socket --quiet
systemctl stop netfoil-imds.service --quiet

set -e

sleep .2
cp systemd/netfoil-imds.socket /usr/lib/systemd/system/netfoil-imds.socket
cp systemd/netfoil-imds.service /usr/lib/systemd/system/netfoil-imds.service
cp systemd/netfoil_imds.slice /usr/lib/systemd/system/netfoil_imds.slice

cp netfoil-imds /usr/sbin/netfoil-imds
systemctl daemon-reload
systemctl start netfoil-imds.socket
systemctl start netfoil-imds.service

systemctl enable netfoil-imds.service
