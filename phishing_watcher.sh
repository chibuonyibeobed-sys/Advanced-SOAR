#!/bin/bash
echo "[*] Phishing Watcher. Paste suspicious URL to check:"
while true
do
  read -p "URL: " URL
  if [[ -n "$URL" ]]
  then
    SRC_IP=$(hostname -I | awk '{print $1}')
    curl -s -X POST http://127.0.0.1:5000/webhook \
    -H "Content-Type: application/json" \
    -d "{\"ip\": \"$SRC_IP\", \"type\": \"phishing\", \"indicator\": \"$URL\"}"
  fi
done
