#!/bin/bash

set -e

CONFIG_DIRECTORY=/etc/netfoil-hi/
mkdir -p "${CONFIG_DIRECTORY}"
mkdir -p "${CONFIG_DIRECTORY}/generic"
cp --update=none config/* "${CONFIG_DIRECTORY}"
