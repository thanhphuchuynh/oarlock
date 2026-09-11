#!/bin/sh
# tcp — ssh -L to a port on the device's own loopback. A port, never a host.
. "$(dirname "$0")/lib.sh"
cd "$ROOT"
say "treadmill-4821 runs a console on its own 127.0.0.1:3000."
say "It has no authentication, because it was never meant to leave the device."
runas "ssh -L 8080:localhost:3000 -N -f treadmill-4821@gateway" \
      "ssh \$SSH_OPTS -L 18080:localhost:3000 -N -f \$DEV@127.0.0.1 2>&1 | grep -v '^oarlock:' || true"
say "That port is reachable here now — and nowhere else on the device's network."
runas "curl -s http://localhost:8080/" \
      "curl -s http://127.0.0.1:18080/ | head -4"
pkill -f 'L 18080' 2>/dev/null
dim ""; dim "# tunnel closed"
beat 2
