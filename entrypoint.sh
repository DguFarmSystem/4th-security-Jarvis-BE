#!/bin/bash
set -e

envsubst < /etc/tbot.yaml.template > /etc/tbot.yaml
tbot start -c /etc/tbot.yaml &

echo "Waiting 10 seconds for identity files to be generated..."
sleep 10

echo "Starting Go application server..."
exec /app/server