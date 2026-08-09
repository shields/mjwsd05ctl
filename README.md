<!--
Copyright © 2026 Michael Shields

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# mjwsd05ctl

Browser-free command-line control of the Xiaomi MJWSD05MMC thermometer/hygrometer:
activate a factory-fresh unit, flash [pvvx custom
firmware](https://github.com/pvvx/ATC_MiThermometer) over the air, configure every
setting, and read live measurements.

Everything the browser-based `TelinkMiFlasher.html` does, from a shell — no Web
Bluetooth, no cloud, no Xiaomi account. Activation is entirely local: an ECDH
handshake with the device itself.

## Install

```sh
uv tool install mjwsd05ctl
```

## Use

### Provisioning a factory-fresh device

Stock firmware ignores both registration and firmware updates unless the device
is in binding mode. Put it there first:

1. Hold **both** buttons until the screen blinks and the device resets.
2. Briefly press the **top** button.
3. Briefly press the **bottom** button — the Bluetooth icon starts flashing.

While it is flashing, run `activate` or `bootstrap`; the latter takes the device
all the way to custom firmware in one step:

```sh
uv run mjwsd05ctl bootstrap --address A4:C1:38:XX:XX:XX
```

That activates the device (recording its Mi token and bind key), flashes the
matching firmware image, and applies a starting configuration.

Skipping steps 2 and 3 is the usual reason this fails. The firmware refuses by
falling silent part way through the handshake rather than by reporting an error,
so the request is simply never answered and `activate` waits out its timeout.
Updates are gated behind the same login, and `flash --skip-activation` does not
get around it: stock firmware hangs up the moment an unauthenticated update
starts.

The individual steps are also available:

```sh
uv run mjwsd05ctl scan                                  # find nearby devices
uv run mjwsd05ctl info --address <mac>                  # what the device reports
uv run mjwsd05ctl activate --address <mac>              # ECDH registration + login
uv run mjwsd05ctl flash --address <mac> --firmware BTH_v58.bin
uv run mjwsd05ctl config --address <mac>                # show current settings
uv run mjwsd05ctl config --address <mac> --set advertising_type=BTHome --set temp_F_or_C=0
uv run mjwsd05ctl config --address <mac> --set-devnum 2 # fleet number; renames it BTH_2
uv run mjwsd05ctl config --address <mac> --set-time --set-bindkey
uv run mjwsd05ctl comfort --address <mac>               # the band the smiley reflects
uv run mjwsd05ctl comfort --address <mac> --set temperature_min=19.5
uv run mjwsd05ctl reboot --address <mac>
uv run mjwsd05ctl read                                  # passive advertisement decode
uv run mjwsd05ctl read --mqtt mqtt://broker.local
```

`read` never connects to anything: it decodes broadcast advertisements, so it
scales to as many devices as are in range. The firmware rebroadcasts each
measurement over several advertising events — redundancy against loss, since
broadcasts are unacknowledged — and `read` reports each measurement once. Each
line starts with the receive time in ISO 8601 UTC; JSON output carries the same
time as `received_at`.
An advertisement that cannot be decoded (no bind key known, say) is reported
every time it is heard, since without the plaintext counter a rebroadcast and
a new failure look alike; `--duplicates` reports every advertisement received.

`info` asks the device for its own Bluetooth MAC address, which is worth having on
macOS, where CoreBluetooth will not tell you what it is. `scan` will
also report MAC addresses.

Devices ship with no PIN and leave their characteristics unsecured, so nothing
bonds by default. Once you have set a PIN, add `--pin` before the subcommand,
such as `mjwsd05ctl --pin reboot --address <mac>`. Entering the code is BlueZ's
business, not this tool's: it asks whichever Bluetooth agent the system has
registered, so on a headless machine keep `bluetoothctl` open alongside with
`agent on`, or pairing will fail with nothing having prompted you.

## Hardware

Tested against Linux with BlueZ and an ASUS USB-BT500 (RTL8761BU), and against
macOS with CoreBluetooth: activation, flashing, and configuration all work
there too. CoreBluetooth hides the device's Bluetooth address behind a per-host
UUID, so on macOS encrypted advertisements cannot be decrypted, saved keys are
filed under an identifier no other machine shares, and pairing cannot be
initiated.

A factory-fresh device must be woken before it accepts a connection — hold both
buttons until the display comes on. Registration then needs the binding-mode
sequence above.

Once the pvvx firmware is on, the device renames itself `BTH_<n>` after its fleet
device number, or `BTH_` and the last three bytes of its address if it has none,
and `scan` reports it under that name. It advertises every five seconds and is
most willing to accept a connection in the moments after it boots. A short press
of the top button — its "connect" function — speeds advertising up and opens a
window in which connecting is reliable; it is worth pressing before any command
that has to connect, and after a flash, before the configuration commands above.

## Development

```sh
make lint       # ruff check, ruff format --check, ty check
make test       # pytest
make coverage
```
