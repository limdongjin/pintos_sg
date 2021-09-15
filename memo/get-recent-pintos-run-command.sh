#!/bin/bash

# $ bash memo/get-recent-pintos-run-command.sh 
HISTFILE=~/.bash_history
set -o history

# or run this command directly
history | grep pintos | grep run
