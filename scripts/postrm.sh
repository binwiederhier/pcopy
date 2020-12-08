#!/bin/sh
set -eu
id pcopy >/dev/null 2>&1 && userdel pcopy
if [ "$1" = "purge" ]; then
  rm -rf /var/cache/pcopy
  rm -rf /etc/pcopy
fi

