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

Take a factory-fresh device all the way to custom firmware in one step:

```sh
mjwsd05ctl bootstrap --address A4:C1:38:XX:XX:XX
```

That activates the device (recording its Mi token and bind key), flashes the
matching firmware image, and applies a starting configuration. The individual
steps are also available:

```sh
mjwsd05ctl scan                                  # find nearby devices
mjwsd05ctl info --address <mac>                  # what the device reports
mjwsd05ctl activate --address <mac>              # ECDH registration + login
mjwsd05ctl flash --address <mac> --firmware BTH_v58.bin
mjwsd05ctl config --address <mac>                # show current settings
mjwsd05ctl config --address <mac> --set advertising_type=BTHome --set temp_F_or_C=0
mjwsd05ctl comfort --address <mac>               # the band the smiley reflects
mjwsd05ctl comfort --address <mac> --set temperature_min=19.5
mjwsd05ctl reboot --address <mac>
mjwsd05ctl read                                  # passive advertisement decode
mjwsd05ctl read --mqtt mqtt://broker.local
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

`info` asks the device for its own Bluetooth address, which is worth having on
macOS, where CoreBluetooth will not tell you what it is.

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
buttons until the display comes on. Stock firmware answers a registration only
after a further arming sequence: hold both buttons until the screen blinks and
the device resets, briefly press the top button, then the bottom one, and the
Bluetooth icon starts flashing. Run `activate` or `bootstrap` while it is;
without this, the registration request is simply never answered.

Once the pvvx firmware is on, the device advertises every five seconds and is
most willing to accept a connection in the moments after it boots. A short
press of the top button — its "connect" function — speeds advertising up and
opens a window in which connecting is reliable.

## Development

```sh
make lint       # ruff check, ruff format --check, ty check
make test       # pytest
make coverage
```
