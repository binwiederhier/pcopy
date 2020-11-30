

mkdir -p ~/.config/pcopy
cd ~/.config/pcopy
openssl req -nodes -x509 -newkey rsa:2048 -keyout server.key -out server.crt -days 365 -subj "/CN=pcopy" -sha256

```
useradd pcopy
mkdir /etc/pcopy /var/cache/pcopy

openssl req \
  -nodes -x509 \
  -newkey rsa:2048 \
  -keyout /etc/pcopy/server.key \
  -out /etc/pcopy/server.crt \
  -subj "/CN=pcopy" \
  -days 1825 \
  -sha256
  
chown pcopy.pcopy /etc/pcopy/server.*
chown pcopy.pcopy /var/cache/pcopy

cat >/etc/systemd/system/pcopy.service << EOL
[Unit]
Description=pcopy server
After=network.target

[Service]
ExecStart=/usr/bin/pcopy serve
Restart=on-failure
User=pcopy
Group=pcopy

[Install]
WantedBy=multi-user.target
EOL

systemctl daemon-reload
systemctl enable pcopy
```