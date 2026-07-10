#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$(dirname "$SCRIPT_DIR")"

sudo cp -r "$AGENT_DIR" /opt

sudo chmod +x /opt/agent/agent
sudo cp "$SCRIPT_DIR/logintel-agent.service" /etc/systemd/system

sudo systemctl daemon-reload
sudo systemctl enable logintel-agent
sudo systemctl start logintel-agent