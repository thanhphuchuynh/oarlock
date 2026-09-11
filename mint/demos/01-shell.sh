#!/bin/sh
# shell — a real SSH prompt on a device with no listener and no open port.
. "$(dirname "$0")/lib.sh"
cd "$ROOT"
say "treadmill-4821 sits behind NAT. It has no sshd, no open port, no host key."
say "It dialled out to the gateway. We connect to the gateway, not to it."
printf '\033[1;31m$\033[0m ssh -p 2222 -i ./operator_key %s@gateway\n' "$DEV"; sleep 0.8
{ sleep 1.6; printf 'uname -sm\n'; sleep 1.8; printf 'sw_vers -productName\n'; sleep 1.8; printf 'exit\n'; } \
  | ssh $SSH_OPTS -tt "$DEV@127.0.0.1" 2>&1
beat 2
