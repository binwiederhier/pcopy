

mkdir -p ~/.config/pcopy
cd ~/.config/pcopy
openssl req -nodes -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -subj "/CN=pcopy" -sha256