#!/bin/sh
# exec — complete argvs, matched element for element. Not "this program, any arguments".
. "$(dirname "$0")/lib.sh"
cd "$ROOT"
say "The device publishes an allow-list of complete argvs. This one is on it:"
runas "ssh treadmill-4821@gateway /usr/bin/uptime" \
      "ssh \$SSH_OPTS \$DEV@127.0.0.1 /usr/bin/uptime 2>&1 | grep -v '^oarlock:'"
say "This one is not. The device refuses it; the gateway never gets to decide."
runas "ssh treadmill-4821@gateway /bin/cat /etc/passwd" \
      "ssh \$SSH_OPTS \$DEV@127.0.0.1 /bin/cat /etc/passwd 2>&1 | grep -v '^oarlock:' | grep -v '^\$'"
beat 2
