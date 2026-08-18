#!/bin/bash
echo "[*] Log Watcher Started. Monitoring /var/log/auth.log..."

tail -F /var/log/auth.log | grep --line-buffered "Failed password" | while read line
do
  IP=$(echo $line | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)

  if [ ! -z "$IP" ]
  then
    echo "[!] Failed login detected from: $IP"
    curl -s -X POST http://127.0.0.1:5000/webhook \
      -H "Content-Type: application/json" \
      -d "{\"ip\": \"$IP\"}"
  fi
done
