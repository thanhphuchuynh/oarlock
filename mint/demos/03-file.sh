#!/bin/sh
# file — one configured root, confined by os.Root so escapes fail in the kernel.
. "$(dirname "$0")/lib.sh"
cd "$ROOT"
say "The file profile reads under one root the device configured."
runas "curl \$GW/devices/treadmill-4821/file?path=device.conf -H \"\$AUTH\"" \
      "curl -s \"\$API/devices/\$DEV/file?path=device.conf\" -H \"Authorization: Bearer \$TOKEN\""
say "A path that climbs out of that root does not fail in a string check."
say "It fails in the kernel, because os.Root is what holds it."
runas "curl \$GW/devices/treadmill-4821/file?path=../../../../etc/passwd -H \"\$AUTH\"" \
      "curl -s \"\$API/devices/\$DEV/file?path=../../../../etc/passwd\" -H \"Authorization: Bearer \$TOKEN\" | python3 -m json.tool | head -6"
beat 2
