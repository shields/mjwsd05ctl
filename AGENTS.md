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

# Agents

Only the things you would otherwise get wrong.

## The firmware is the specification

Three protocols here are undocumented, and where a published specification
disagrees with the device, the device wins. Check claims against
[pvvx/ATC_MiThermometer](https://github.com/pvvx/ATC_MiThermometer) — the C
sources for the firmware side, and `TelinkMiFlasher.html` for the only existing
implementation of the Xiaomi handshake. Specifically:

- The Telink image header's CRC-32 is `zlib.crc32(data) ^ 0xFFFFFFFF`. A plain
  `zlib.crc32` rejects every real image.
- The pvvx firmware keeps a decoy FE95 service: its GATT table ends with a bare
  primary-service declaration and a "Mi" user description (`app_att.c`), no
  characteristics. So the service's presence cannot tell stock from pvvx —
  the reference flasher keys "Detected Mi device" off the vendor service
  `ebe0ccb0-…` instead, and `cli.has_mi_auth` checks for the 0x0010 control
  characteristic itself. Flashing a converted device with the service check in
  place dies in `MiAuth.open` on the missing characteristic.
- Encrypted BTHome advertisements from this firmware use **no** associated data,
  though [bthome.io](https://bthome.io/format/) specifies `0x11`. The pvvx and
  ATC formats do use `0x11`, and put the address in the nonce reversed, where
  BTHome uses display order.
- `cfg_t` bit-fields are allocated from the least significant bit, as C does, so
  each byte's fields appear in `config.CFG` in the reverse of their declaration
  order in `src/app.h`.
- A configuration reply is one byte longer than the configuration: the firmware
  notifies `sizeof(cfg) + 3` bytes out of a `sizeof(cfg) + 2` buffer. Trailing
  bytes are expected.
- A reply does not always carry the opcode that was sent. `CFG_DEF` is answered
  through `ble_send_cfg()`, whose opcode byte is only ever written by
  `test_config()` in `app.c` — which the reset path itself calls, stamping it
  back to `CMD_ID_CFG`. So a reset is answered `0x55`, not `0x56`;
  `Session.request` takes `expect=` for this. Every other opcode this package
  sends goes through the firmware's generic `send_buf[0] = cmd` path and is
  echoed faithfully.
- Extended OTA reports progress, not just completion. `clear_ota_area()` pushes
  `EXT_OTA_EVENT` (4) once per flash sector erased, between the `EXT_OTA_BUSY`
  (2) acknowledgement and the final `EXT_OTA_READY` (3). Treating anything other
  than 2 as a failure aborts on the first progress tick. Status 0 is not an
  acknowledgement either: it means the address was below `BIG_OTA2_FADDR` and
  nothing started.
- The update slot is not one size. Stock firmware lends out all 208 KiB, custom
  firmware keeps 128 KiB — and 112 KiB on hardware id 12, which the reference
  flasher singles out (`TelinkMiFlasher.html:2373`) and the C does not explain.
  Anything larger has to go through the extended area first, which erases the
  stored Mi Home keys and the measurement history, so do not widen the condition
  that triggers it.
- Addresses come back from `CMD_ID_DEV_MAC` least significant byte first, the
  reverse of how they are written down, and the reply is `[len][mac][rand]`
  rather than bare bytes. The random static address reuses the public address's
  first three bytes and always ends `0xC0`. Sending `[0x10, 0x00]` does not read
  the address — it erases the MAC sector and resets the device — so a read must
  carry no payload at all.
- Comfort limits (`CMD_ID_COMFORT`) are hundredths, and `scomfort_t` is signed
  for temperature and unsigned for humidity. Parsing both the same way turns
  −5 °C into 655 °C.

When changing any of these, update the test that pins it. The tests derive
expected values independently — HKDF written out by hand, ciphertext built the
way the C builds it — so that a mistake cannot be made twice and cancel out.

## Binding mode

Registration has a precondition no amount of code satisfies: the thermometer
must have had its previous binding cleared and be in binding mode, which on this
model means holding both buttons until the screen blinks and the device resets,
then a brief press of the top button and then the bottom one, until the
Bluetooth icon flashes
([pvvx/ATC_MiThermometer#505](https://github.com/pvvx/ATC_MiThermometer/issues/505)).

A device that is not in binding mode does not say so. It answers
`MI_CMD_REGISTER_START` with `000000000100`, asks to restart the exchange with
`010001000000`, and then ignores the `000000030400` public-key announcement
indefinitely — the link stays up and re-sending `a2000000` still draws a fresh
reply, so only the one step is dead. `TelinkMiFlasher.html` sends the same bytes
in the same order and hangs the same way, so a stall there is not evidence of a
transcription error, and resends and longer settling times do not help. This is
why `register` alone passes a hint to `_pump`.

The opening answer is not a binding indicator, however much the reference
flasher's `is_activated` reads like one. A device straight from the factory,
never bound and with no Mi Home account anywhere in the picture, answers
`000000000200` — the branch that looks like "already activated" — and follows it
with a device id it already holds, `\0blt.3.129v…g00`, in two chunks behind a
four-byte header. It then dies at `000000030400` exactly as a `000000000100`
device does. So neither opening tells you whether anything needs clearing, and
reading `000000000200` as a leftover Mi Home registration sends you looking for
an account to delete that may not exist. Only the buttons decide.

Stalling is not the only shape the refusal takes: the same device has been seen
to drop the link at `000000030400` rather than ignore it. Which of the two you
get is not yours to choose, so `_pump` hangs the hint on a `TransportError` as
well as on a timeout; a refusal that came back as a bare "device disconnected"
told the reader nothing they could act on.

## Hardware-free testing

`tests/test_miauth.py` drives the registration and login state machines against
a fake device that plays the other half of the handshake, including both login
variants. That is the only way this code is exercised without a thermometer, so
keep it working; a change to `miauth` that the fake does not reach is untested.

## Coverage

`make coverage` enforces 100% of statements and branches; there is no
`# pragma: no cover` anywhere and adding one needs a reason. The number is a
floor, not a goal — it was reached and then checked by mutation testing, which
found that a quarter of the newly covered lines had no assertion behind them.
Two shipped bugs were hiding under a clean coverage report. When you cover
something new, inject the bug you are guarding against and confirm a test fails.

Coverage.py cannot see a branch whose two outcomes live on one source line: a
same-line `X if Y else Z`, a comprehension's `if`, and `or`/`and` fallback chains
outside an `if` all report as fully covered when only one side ever ran. Several
gaps hid there. Prefer a statement `if` where the two sides are worth testing
separately.

## Pairing

Do not call `pair()`. The firmware leaves its characteristics at `No_Security`
unless a PIN has been set, so bonding buys nothing and is unreliable on some
stacks. `transport.connect` takes `pair=`, and the CLI's `--pin` sets it, for
the PIN case only.

Bleak has no passkey API: its BlueZ backend calls `Device1.Pair()` and registers
no `org.bluez.Agent1`, so the code is collected by whatever agent the system
already has. Do not document `--pin` as prompting for anything.

## Platform

Provisioning works on both Linux/BlueZ and macOS. CoreBluetooth reports a
per-host UUID instead of the hardware address, so encrypted advertisements
cannot be decrypted on macOS — `reader` detects this and says so rather than
failing obscurely. Three more macOS lessons cost an evening of a device that
would not answer or advertise until reset; do not undo their fixes:

- CoreBluetooth connection requests never expire. A `BleakClient.connect` that
  fails must still be `disconnect()`ed (`transport.connect` does), or the OS
  daemon keeps the request pending, connects the moment the device next
  advertises, and holds it — invisible and unreachable — indefinitely. The
  firmware stops advertising while it believes a connection is up and only
  re-arms advertising in its disconnect callback, so a phantom central keeps
  the device dark until it is physically reset.
- A write-without-response can vanish in the first moments of a connection,
  observed while the firmware's connection-parameter update is in flight; the
  same write two seconds later is answered in milliseconds. `Session.request`
  resends unanswered commands, which is safe because every opcode it carries
  is idempotent, and it first discards stale queued replies, because a resend
  can double-answer and replies carry no request correlation — keep all of
  these properties when adding commands. `RESEND_INTERVAL` bounds the write as
  well as the wait for a reply: a write that hangs is the case resending is
  for, and one issued outside that scope holds up the resend it should be
  causing.
- The flashed firmware advertises every five seconds by default and accepts
  connections most reliably right after boot or a top-button press (the pvvx
  "connect" function), which is why `bootstrap` retries its post-reboot
  reconnect instead of scanning once.
- Bleak's `disconnected_callback` does not always arrive. Two runs of the same
  command dropped at the same point in the same exchange; one raised out of
  `Link.take` at once, the other waited out the caller's whole 60 s deadline
  with the disconnect already logged by Bleak's own backend. Reading the chain
  from `centralManager_didDisconnectPeripheral_error_` to the callback turns up
  nothing conditional, so do not assume the event will be set. `Link` asks the
  platform rather than waiting to be told, in the two places a wait can begin:
  `_check_connected` reads `is_connected` on the way into every method, and
  `take` polls it every `DISCONNECT_POLL` while blocked. Both record what they
  find by setting the event, so one discovery serves the rest of the link. Do
  not reduce either to whichever half looks redundant — the event alone is what
  goes missing, and a flag that was never set reads exactly like a healthy
  link. For the same reason, wait for notifications through `take` rather than
  on a queue directly: `request_ext_ota` did the latter, and so would have
  spent its whole two-minute erase deadline on a dead link, after discarding
  the Mi Home keys and the measurement history.
- A write has the same exposure and nothing underneath it: CoreBluetooth's
  write-with-response awaits its delegate future bare, where the read path
  carries its own deadline, so `Link.write` imposes `WRITE_TIMEOUT`. Without it
  an unanswered write is charged to whichever exchange it belonged to, and
  `MiAuth._pump` would report a device that never answered rather than a write
  that was never acknowledged. It is the backstop for callers with no cadence
  of their own, `ota`'s update stream above all; `Session.request` bounds its
  own writes more tightly, and should. Write-without-response cannot hang this
  way — CoreBluetooth does not await anything for it — which is why the update
  stream is unaffected in practice.

## Lint

`.ruff.toml` is the shared configuration from `shields/right-answers` plus two
additions, both commented in the file: `ASYNC109` is off because the timeouts
here are protocol deadlines rather than caller policy, and `tests/` relaxes the
rules that fight pytest.
