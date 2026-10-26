#!/bin/bash

set -e

instance="$1"
if [[ -z "$instance" ]]; then
	echo "systemd instance must be specified, e.g. 'default'"
	exit 1
fi

echo "instance $instance"

CONFIG_DIRECTORY="/etc/netfoil-hi/$instance"
mkdir -p "${CONFIG_DIRECTORY}"
mkdir -p "${CONFIG_DIRECTORY}/generic"
cp -r --update=none config/* "${CONFIG_DIRECTORY}"
