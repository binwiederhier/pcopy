#!/bin/sh
set -eu
id pcopy >/dev/null 2>&1 || useradd --system --no-create-home pcopy
chown pcopy.pcopy /var/cache/pcopy
chmod 700 /var/cache/pcopy
chown pcopy.pcopy /etc/pcopy
chmod 700 /etc/pcopy
systemctl daemon-reload
if systemctl is-active -q pcopy; then
  systemctl restart pcopy
fi
exit 0
