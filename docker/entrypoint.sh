#!/usr/bin/env bash

# Directory to watch for changes
watched_directory="/app"

# Command to restart the server
restart_command="python phxd &"

# Start the server initially
echo "Starting Hotline Server.. for real."
python phxd &

# PID of the server process
server_pid=$!

# # Watch for file changes and restart the server on change
while true; do
    inotifywait -e modify,move,create,delete -r "$watched_directory"
    echo "File change detected. Restarting Hotline Server..."
    kill -9 $server_pid
    python phxd &
    server_pid=$!
done
