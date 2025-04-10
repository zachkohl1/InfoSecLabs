#!/bin/bash

ACTIVE_DIR="./active"
UPDATES_DIR="./updates"
LOG_FILE="update.log"

# Log time
{
    echo "[INFO] Update started at $(date)"

    echo "[INFO] Killing running server and client..."
    pkill -f "$ACTIVE_DIR/server"
    pkill -f "$ACTIVE_DIR/client"
    sleep 1

    echo "[INFO] Replacing active binaries..."
    cp -f "$UPDATES_DIR/server_v2" "$ACTIVE_DIR/server"
    cp -f "$UPDATES_DIR/client_v2" "$ACTIVE_DIR/client"
    chmod +x "$ACTIVE_DIR/server" "$ACTIVE_DIR/client"

    # echo "[INFO] Launching new server and client in terminals..."
    # gnome-terminal -- bash -c "$ACTIVE_DIR/server; exec bash" &
    # sleep 2
    # gnome-terminal -- bash -c "$ACTIVE_DIR/client; exec bash" &

    echo "[INFO] Update complete."
} >> "$LOG_FILE" 2>&1