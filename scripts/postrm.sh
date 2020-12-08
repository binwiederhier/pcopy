#!/bin/sh
set -eu
systemctl stop pcopy >/dev/null 2>&1 || true
if [ "$1" = "purge" ]; then
  id pcopy >/dev/null 2>&1 && userdel pcopy
  rm -rf /var/cache/pcopy
  rm -rf /etc/pcopy
fi

