# Shared presentation for the recorded demos.
#
# Every scene runs a real command against a real gateway — nothing here fakes output.
# `runas` exists because the command an operator would type and the command this script
# must run are not quite the same: the demo gateway listens on 127.0.0.1:2222 with a key
# in ./demo, and printing that noise would teach the reader the wrong shape. The shown
# form is the honest one; the run form is the same command with this lab's addresses.
set -u
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SSH_OPTS="-p 2222 -i demo/operator_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR"
DEV=treadmill-4821
API=http://127.0.0.1:8443/api/v1
TOKEN=dev-token-long-enough-for-the-check
# Shown in the demos as the shape a reader would actually write.
GW=https://gw.example.org/api/v1
AUTH="Authorization: Bearer $TOKEN"

dim()   { printf '\033[2m%s\033[0m\n' "$*"; }
say()   { printf '\n\033[2m# %s\033[0m\n' "$*"; sleep 1.3; }
prompt(){ printf '\033[1;31m$\033[0m %s\n' "$*"; sleep 0.8; }
runas() { prompt "$1"; shift; eval "$@"; sleep 1.4; }
beat()  { sleep "${1:-1.5}"; }
