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
mjwsd05ctl activate --address <mac>              # ECDH registration + login
mjwsd05ctl flash --address <mac> --firmware BTH_v58.bin
mjwsd05ctl config --address <mac>                # show current settings
mjwsd05ctl config --address <mac> --set advertising_type=BTHome --set temp_F_or_C=0
mjwsd05ctl read                                  # passive advertisement decode
mjwsd05ctl read --mqtt mqtt://broker.local
```

`read` never connects to anything: it decodes broadcast advertisements, so it
scales to as many devices as are in range.

## Hardware

Tested against Linux with BlueZ and an ASUS USB-BT500 (RTL8761BU). macOS works
for reading and for most GATT work, but CoreBluetooth hides the device's
Bluetooth address behind a per-host UUID and cannot initiate pairing, so prefer
Linux for provisioning.

A factory-fresh device must be woken before it accepts a connection — hold both
buttons until the display comes on.

## Development

```sh
make lint       # ruff check, ruff format --check, ty check
make test       # pytest
make coverage
```
