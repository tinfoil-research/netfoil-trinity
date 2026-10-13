#!/bin/bash

set -e

CONFIG_DIRECTORY=/etc/netfoil-time/
mkdir -p "${CONFIG_DIRECTORY}"
cp --update=none config/* "${CONFIG_DIRECTORY}"
