# Copyright © 2026 Michael Shields
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for the Xiaomi handshake.

The key derivations are checked against HKDF and HMAC written out by hand, so a
mistake in `miauth` cannot be masked by making the same mistake twice. The state
machine is driven by a fake device that plays the sequence `TelinkMiFlasher.html`
implies, which is the only way to exercise it without hardware.
"""

import asyncio
import hashlib
import hmac
import logging
from collections.abc import Sequence

import pytest
from Crypto.Cipher import AES
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from mjwsd05ctl import miauth, transport
from mjwsd05ctl.constants import (
    MI_AUTH_CONTROL_CHAR,
    MI_AUTH_DATA_CHAR,
    MI_DID_AAD,
    MI_DID_NONCE,
    MI_LOGIN_INFO,
    MI_SETUP_INFO,
)
from mjwsd05ctl.errors import ActivationError, TransportError
from mjwsd05ctl.miauth import MiAuth, MiKeys


def hkdf(ikm: bytes, salt: bytes | None, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF-SHA256, written out independently of `cryptography`."""
    prk = hmac.new(salt or b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def test_setup_keys_match_an_independent_hkdf() -> None:
    shared = bytes(range(32))
    token, bindkey, wrapping = miauth.derive_setup_keys(shared)
    expected = hkdf(shared, None, MI_SETUP_INFO, 64)
    assert token == expected[0:12]
    assert bindkey == expected[12:28]
    assert wrapping == expected[28:44]
    assert len(token) == 12
    assert len(bindkey) == 16


def test_login_proofs_match_an_independent_derivation() -> None:
    token = bytes(range(12))
    ours = bytes(range(16))
    theirs = bytes(range(16, 32))
    expected, sent = miauth.derive_login_proofs(token, ours, theirs)

    derived = hkdf(token, ours + theirs, MI_LOGIN_INFO, 64)
    assert expected == hmac.new(derived[0:16], theirs + ours, hashlib.sha256).digest()
    assert sent == hmac.new(derived[16:32], ours + theirs, hashlib.sha256).digest()
    # The two proofs use different keys over different orderings, so a device
    # cannot replay ours back at us.
    assert expected != sent


def test_wrapped_device_id_decrypts_under_the_same_parameters() -> None:
    key = bytes(range(16))
    device_id = miauth.generate_device_id()
    wrapped = miauth.wrap_device_id(key, device_id)
    assert len(wrapped) == len(device_id) + 4

    cipher = AES.new(key, AES.MODE_CCM, nonce=MI_DID_NONCE, mac_len=4)
    cipher.update(MI_DID_AAD)
    assert cipher.decrypt_and_verify(wrapped[:-4], wrapped[-4:]) == device_id


def test_generated_device_id_has_the_shape_mi_home_uses() -> None:
    device_id = miauth.generate_device_id()
    assert len(device_id) == 20
    assert device_id.startswith(b"\x00blt.3.129v")
    assert device_id.endswith(b"g00")
    assert device_id[11:17].isalnum()
    assert miauth.generate_device_id() != device_id


def test_chunks_frame_payloads_the_way_the_protocol_expects() -> None:
    # A public key body is 64 bytes: three full chunks and a short one.
    framed = miauth.chunks(bytes(range(64)))
    assert [chunk[:2] for chunk in framed] == [
        b"\x01\x00",
        b"\x02\x00",
        b"\x03\x00",
        b"\x04\x00",
    ]
    assert [len(chunk) - 2 for chunk in framed] == [18, 18, 18, 10]
    assert b"".join(chunk[2:] for chunk in framed) == bytes(range(64))


def test_chunks_of_a_wrapped_device_id_split_in_two() -> None:
    framed = miauth.chunks(bytes(range(24)))
    assert len(framed) == 2
    assert [len(chunk) - 2 for chunk in framed] == [18, 6]


def test_mi_keys_reject_wrong_lengths() -> None:
    with pytest.raises(ActivationError, match="token must be 12 bytes"):
        MiKeys(token=b"short", bindkey=bytes(16), device_id=b"")
    with pytest.raises(ActivationError, match="bind key must be 16 bytes"):
        MiKeys(token=bytes(12), bindkey=b"short", device_id=b"")


ACK = bytes.fromhex("00000100")
READY = bytes.fromhex("00000101")
ACK_SHORT = bytes.fromhex("00000300")


class FakeDevice:
    """The far side of the handshake, following the reference flasher's script.

    Progress is tracked as an explicit phase because several messages, notably
    the bare acknowledgements, mean different things at different points.

    `single_shot` picks between the two login variants the client must handle:
    one that exchanges randoms and proofs in chunks, and one that sends each in
    a single message.
    """

    def __init__(self, *, single_shot: bool = False, wrong_proof: bool = False) -> None:
        self.single_shot = single_shot
        self.wrong_proof = wrong_proof
        self.private_key = ec.generate_private_key(ec.SECP256R1())
        self.phase = "idle"
        self.client_public = bytearray()
        self.token = b""
        self.bindkey = b""
        self.wrapping_key = b""
        self.wrapped_did = bytearray()
        self.our_random = bytes(range(100, 116))
        self.client_random = b""
        self.received_proof = bytearray()
        self.outbox: asyncio.Queue[tuple[str, bytes]] | None = None
        self.logged_in = False

    def send(self, uuid: str, payload: bytes) -> None:
        assert self.outbox is not None
        self.outbox.put_nowait((uuid, payload))

    def data(self, payload: bytes) -> None:
        self.send(MI_AUTH_DATA_CHAR, payload)

    def status(self, code: int) -> None:
        self.send(MI_AUTH_CONTROL_CHAR, bytes([code, 0, 0, 0]))

    def public_bytes(self) -> bytes:
        return self.private_key.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )

    async def handle(self, uuid: str, payload: bytes) -> None:
        if uuid == MI_AUTH_CONTROL_CHAR:
            self.handle_control(payload)
        else:
            self.handle_data(payload)

    def handle_control(self, payload: bytes) -> None:
        match payload.hex():
            case "a2000000":  # start registration
                self.phase = "offered"
                self.data(bytes.fromhex("000000000100"))  # not yet activated
            case "13000000":  # the client says it verified us
                self.status(miauth.MiStatus.REG_SUCCESS)
            case "24000000":  # start login
                self.phase = "login"

    def handle_data(self, payload: bytes) -> None:
        index = payload[0] if len(payload) >= 2 and payload[1] == 0 else 0
        match (self.phase, payload):
            case ("offered", p) if p == READY:
                self.phase = "prompted"
                self.data(bytes.fromhex("010001000000"))
            case (_, p) if p == bytes.fromhex("000000030400"):
                self.phase = "public_key"
                self.data(READY)
            case ("public_key", _) if index:
                self.collect_public_key(index, payload[2:])
            case ("sent_public_key", p) if p == bytes.fromhex("000000000200"):
                self.phase = "device_id"
                self.data(READY)
            case ("device_id", _) if index:
                self.collect_device_id(index, payload[2:])
            case ("login", p) if p == bytes.fromhex("0000000b0100"):
                self.data(READY)
            case ("login", _) if index:
                self.collect_random(payload[2:])
            case ("chunked_random", p) if p == READY:
                self.phase = "sent_random"
                self.data(bytes([1, 0]) + self.our_random)
            case ("sent_random", p) if p == ACK:
                self.phase = "offered_proof"
                self.data(bytes.fromhex("0000000c0200"))
            case ("offered_proof", p) if p == READY:
                self.phase = "sent_proof"
                for chunk in miauth.chunks(self.our_proof()):
                    self.data(chunk)
            case ("sent_proof", p) if p == bytes.fromhex("0000000a0200"):
                self.phase = "await_proof"
                self.data(READY)
            case ("short_random", p) if p == ACK_SHORT:
                self.phase = "short_proof"
                self.data(bytes.fromhex("0000020c") + self.our_proof())
            case ("short_proof", p) if p == bytes.fromhex("0000000a0100"):
                self.phase = "await_proof"
                self.data(READY)
            case ("await_proof", _) if index:
                self.collect_proof(payload[2:])

    def collect_public_key(self, index: int, body: bytes) -> None:
        if index == 1:
            self.client_public = bytearray(b"\x04")
        self.client_public += body
        if index != 4:
            return
        peer = ec.EllipticCurvePublicKey.from_encoded_point(
            ec.SECP256R1(), bytes(self.client_public)
        )
        shared = self.private_key.exchange(ec.ECDH(), peer)
        self.token, self.bindkey, self.wrapping_key = miauth.derive_setup_keys(shared)
        self.phase = "sent_public_key"
        for chunk in miauth.chunks(self.public_bytes()[1:]):
            self.data(chunk)

    def collect_device_id(self, index: int, body: bytes) -> None:
        if index == 1:
            self.wrapped_did = bytearray()
        self.wrapped_did += body
        if index == 2:
            self.phase = "registered"
            self.data(ACK)

    def collect_random(self, body: bytes) -> None:
        self.client_random = body
        if self.single_shot:
            self.phase = "short_random"
            self.data(bytes.fromhex("0000020d") + self.our_random)
        else:
            self.phase = "chunked_random"
            self.data(bytes.fromhex("0000000d0100"))

    def collect_proof(self, body: bytes) -> None:
        self.received_proof += body
        _, expected = miauth.derive_login_proofs(
            self.token, self.client_random, self.our_random
        )
        if bytes(self.received_proof) != expected:
            return
        self.logged_in = True
        self.data(ACK)
        self.status(miauth.MiStatus.LOG_SUCCESS)

    def our_proof(self) -> bytes:
        expected, _ = miauth.derive_login_proofs(
            self.token, self.client_random, self.our_random
        )
        return bytes(len(expected)) if self.wrong_proof else expected


class FakeLink:
    """Just enough of `transport.Link` for `MiAuth`."""

    def __init__(self, device: FakeDevice) -> None:
        self.device = device
        self.queue: asyncio.Queue[tuple[str, bytes]] = asyncio.Queue()
        self.writes: list[tuple[str, bytes]] = []
        self._disconnected = asyncio.Event()
        device.outbox = self.queue

    def disconnect(self) -> None:
        self._disconnected.set()

    async def subscribe_tagged(
        self, uuids: Sequence[str]
    ) -> asyncio.Queue[tuple[str, bytes]]:
        assert set(uuids) == {MI_AUTH_CONTROL_CHAR, MI_AUTH_DATA_CHAR}
        return self.queue

    async def take(self, queue: asyncio.Queue[tuple[str, bytes]]) -> tuple[str, bytes]:
        # Borrow the real implementation so the pump is tested against the
        # actual disconnect semantics, not a lenient imitation.
        return await transport.Link.take(self, queue)  # ty: ignore[invalid-argument-type]

    async def write(
        self, uuid: str, data: bytes, *, response: bool | None = None
    ) -> None:
        del response
        self.writes.append((uuid, data))
        await self.device.handle(uuid, data)


@pytest.fixture(autouse=True)
def _no_settling(monkeypatch: pytest.MonkeyPatch) -> None:
    """The protocol's inter-command pauses only matter against real hardware."""
    monkeypatch.setattr(miauth, "SETTLE", 0.0)


async def run_flow(device: FakeDevice) -> tuple[MiAuth, FakeLink, MiKeys]:
    link = FakeLink(device)
    auth = MiAuth(link)  # ty: ignore[invalid-argument-type]
    await auth.open()
    keys = await auth.register(timeout=5.0)
    return auth, link, keys


async def test_a_disconnect_fails_the_handshake_immediately() -> None:
    # A dead link must fail the pump at once, not sit out the whole protocol
    # timeout waiting for notifications that can no longer arrive.
    class DeafDevice(FakeDevice):
        async def handle(self, uuid: str, payload: bytes) -> None:
            del uuid, payload

    link = FakeLink(DeafDevice())
    auth = MiAuth(link)  # ty: ignore[invalid-argument-type]
    await auth.open()
    link.disconnect()
    async with asyncio.timeout(1):
        with pytest.raises(TransportError, match="device disconnected"):
            await auth.register(timeout=5.0)


async def test_registration_derives_the_same_keys_as_the_device() -> None:
    device = FakeDevice()
    _, _, keys = await run_flow(device)
    assert keys.token == device.token
    assert keys.bindkey == device.bindkey
    assert len(keys.token) == 12
    assert len(keys.bindkey) == 16


async def test_registration_sends_the_wrapped_device_id() -> None:
    device = FakeDevice()
    _, link, keys = await run_flow(device)
    written = [data for uuid, data in link.writes if uuid == MI_AUTH_DATA_CHAR]
    did_chunks = [chunk for chunk in written if chunk[:2] in (b"\x01\x00", b"\x02\x00")]
    # The last two indexed writes are the wrapped identifier.
    wrapped = did_chunks[-2][2:] + did_chunks[-1][2:]
    assert len(wrapped) == len(keys.device_id) + 4

    # Decrypt with the device's own wrapping key, independently of
    # `miauth.wrap_device_id`, to pin down that these bytes actually unwrap to
    # the id the client generated rather than merely being the right length.
    cipher = AES.new(device.wrapping_key, AES.MODE_CCM, nonce=MI_DID_NONCE, mac_len=4)
    cipher.update(MI_DID_AAD)
    assert cipher.decrypt_and_verify(wrapped[:-4], wrapped[-4:]) == keys.device_id


@pytest.mark.parametrize("single_shot", [False, True])
async def test_login_completes_in_both_variants(single_shot: bool) -> None:
    device = FakeDevice(single_shot=single_shot)
    auth, _, keys = await run_flow(device)
    await auth.login(keys.token, timeout=5.0)
    assert device.logged_in


async def test_login_refuses_a_device_that_cannot_prove_the_token() -> None:
    device = FakeDevice(single_shot=True, wrong_proof=True)
    auth, _, keys = await run_flow(device)
    with pytest.raises(ActivationError, match="prove it holds the token"):
        await auth.login(keys.token, timeout=5.0)


async def test_login_rejects_a_token_of_the_wrong_length() -> None:
    auth = MiAuth(FakeLink(FakeDevice()))  # ty: ignore[invalid-argument-type]
    await auth.open()
    with pytest.raises(ActivationError, match="token must be 12 bytes"):
        await auth.login(b"nope")


async def test_activation_fails_loudly_when_the_device_says_no() -> None:
    class Refusing(FakeDevice):
        def handle_control(self, payload: bytes) -> None:
            if payload.hex() == "a2000000":
                self.status(miauth.MiStatus.ERR_REGISTERED)

    auth = MiAuth(FakeLink(Refusing()))  # ty: ignore[invalid-argument-type]
    await auth.open()
    with pytest.raises(ActivationError, match="already registered"):
        await auth.register(timeout=5.0)


async def test_register_without_open_is_an_error() -> None:
    auth = MiAuth(FakeLink(FakeDevice()))  # ty: ignore[invalid-argument-type]
    with pytest.raises(ActivationError, match="open"):
        await auth.register(timeout=5.0)


class SilentDevice(FakeDevice):
    """A device that is in range but never answers, as a flat battery would."""

    async def handle(self, uuid: str, payload: bytes) -> None:
        del uuid, payload


async def test_an_unresponsive_device_raises_a_domain_error_not_a_timeout() -> None:
    auth = MiAuth(FakeLink(SilentDevice()))  # ty: ignore[invalid-argument-type]
    await auth.open()
    with pytest.raises(ActivationError, match="did not respond"):
        await auth.register(timeout=0.05)


async def test_an_unresponsive_device_fails_login_the_same_way() -> None:
    auth = MiAuth(FakeLink(SilentDevice()))  # ty: ignore[invalid-argument-type]
    await auth.open()
    with pytest.raises(ActivationError, match="did not respond"):
        await auth.login(bytes(12), timeout=0.05)


async def test_login_without_open_is_an_error() -> None:
    auth = MiAuth(FakeLink(FakeDevice()))  # ty: ignore[invalid-argument-type]
    with pytest.raises(ActivationError, match="open"):
        await auth.login(bytes(12))


async def test_activate_registers_then_logs_in_with_the_derived_token() -> None:
    device = FakeDevice()
    auth = MiAuth(FakeLink(device))  # ty: ignore[invalid-argument-type]
    await auth.open()
    keys = await auth.activate()
    assert keys.token == device.token
    assert keys.bindkey == device.bindkey
    assert device.logged_in


async def test_an_unrecognised_status_code_is_logged_and_does_not_abort_registration(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="mjwsd05ctl.miauth")

    class ChattyStatus(FakeDevice):
        def handle_control(self, payload: bytes) -> None:
            if payload.hex() == "a2000000":
                self.status(0x99)  # not a member of MiStatus
            super().handle_control(payload)

    device = ChattyStatus()
    _, _, keys = await run_flow(device)
    assert keys.token == device.token
    assert "unrecognised status 99000000" in caplog.text


async def test_an_empty_status_notification_is_ignored() -> None:
    class SilentStatus(FakeDevice):
        def handle_control(self, payload: bytes) -> None:
            if payload.hex() == "a2000000":
                self.send(MI_AUTH_CONTROL_CHAR, b"")
            super().handle_control(payload)

    device = SilentStatus()
    _, _, keys = await run_flow(device)
    assert keys.token == device.token


async def test_a_recognised_in_progress_status_is_logged_and_does_not_end_the_pump(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="mjwsd05ctl.miauth")

    class VerifyingStatus(FakeDevice):
        def handle_control(self, payload: bytes) -> None:
            if payload.hex() == "a2000000":
                self.status(miauth.MiStatus.REG_VERIFY_SUCC)
            super().handle_control(payload)

    device = VerifyingStatus()
    _, _, keys = await run_flow(device)
    assert keys.token == device.token
    assert "registration verify successful" in caplog.text


async def test_a_repeat_login_status_ends_login_without_raising() -> None:
    """0xE2 ("already logged in") is a terminal success, not a failure.

    The reference flasher treats a device that reports it is already logged
    in as fine to proceed with, so `login()` must return rather than sit in
    the pump loop waiting for a status it will never see.
    """

    class AlreadyLoggedIn(FakeDevice):
        def handle_control(self, payload: bytes) -> None:
            if payload.hex() == "24000000":  # login start
                self.status(miauth.MiStatus.ERR_REPEAT_LOGIN)
                return
            super().handle_control(payload)

    device = AlreadyLoggedIn()
    auth, _, keys = await run_flow(device)
    await auth.login(keys.token, timeout=0.2)
    # The handshake never ran; the short timeout above is only there to keep
    # a regression from hanging the test suite rather than to allow one.
    assert not device.logged_in


async def test_a_relogin_request_to_restart_login_repeats_the_handshake() -> None:
    class RestartingLogin(FakeDevice):
        def __init__(self) -> None:
            super().__init__()
            self.restarted = False

        def handle_data(self, payload: bytes) -> None:
            if (
                self.phase == "login"
                and payload == bytes.fromhex("0000000b0100")
                and not self.restarted
            ):
                self.restarted = True
                # Prefix "000004" plus reason byte 1: "please log in again".
                self.data(bytes.fromhex("00000401"))
                return
            super().handle_data(payload)

    login_start = bytes.fromhex("24000000")
    device = RestartingLogin()
    auth, link, keys = await run_flow(device)
    await auth.login(keys.token, timeout=5.0)
    assert device.logged_in
    control_writes = [d for u, d in link.writes if u == MI_AUTH_CONTROL_CHAR]
    assert control_writes.count(login_start) == 2  # start, then again after the restart
    data_writes = [d for u, d in link.writes if u == MI_AUTH_DATA_CHAR]
    assert bytes.fromhex("00000501") in data_writes  # the client acked the request


async def test_a_relogin_request_with_another_reason_only_acknowledges() -> None:
    class PingingLogin(FakeDevice):
        def __init__(self) -> None:
            super().__init__()
            self.pinged = False

        def handle_data(self, payload: bytes) -> None:
            if (
                self.phase == "login"
                and payload == bytes.fromhex("0000000b0100")
                and not self.pinged
            ):
                self.pinged = True
                # Prefix "000004" plus a reason byte other than 1: not a login restart.
                self.data(bytes.fromhex("00000402"))
                self.data(READY)  # the device carries on as if nothing happened
                return
            super().handle_data(payload)

    login_start = bytes.fromhex("24000000")
    device = PingingLogin()
    auth, link, keys = await run_flow(device)
    await auth.login(keys.token, timeout=5.0)
    assert device.logged_in
    control_writes = [d for u, d in link.writes if u == MI_AUTH_CONTROL_CHAR]
    assert control_writes.count(login_start) == 1  # a non-restart reason skips a repeat
    data_writes = [d for u, d in link.writes if u == MI_AUTH_DATA_CHAR]
    assert bytes.fromhex("00000502") in data_writes  # still acked the request


async def test_a_single_message_known_id_restarts_registration() -> None:
    known_id = miauth.generate_device_id()

    class KnownDeviceIdSingleMessage(FakeDevice):
        def handle_control(self, payload: bytes) -> None:
            if payload.hex() == "a2000000":
                self.phase = "offered"
                # The 8-byte header the device uses when it reports an id it already
                # holds in a single message, rather than the usual two chunks.
                self.data(bytes.fromhex("0000020001000000") + known_id)
                return
            super().handle_control(payload)

    device = KnownDeviceIdSingleMessage()
    _, _, keys = await run_flow(device)
    assert keys.device_id == known_id
    assert keys.token == device.token


async def test_an_activated_device_reports_its_known_id_in_two_chunks() -> None:
    known_id = miauth.generate_device_id()

    class ActivatedKnownId(FakeDevice):
        def handle_control(self, payload: bytes) -> None:
            if payload.hex() == "a2000000":
                self.phase = "offered"
                self.data(bytes.fromhex("000000000200"))  # already activated
                return
            super().handle_control(payload)

        def handle_data(self, payload: bytes) -> None:
            if payload == READY and self.phase == "offered":
                # A 4-byte header the client discards, then the id it already knows,
                # split into indexed chunks like every other payload.
                header = bytes(4)
                for chunk in miauth.chunks(header + known_id):
                    self.data(chunk)
                return
            super().handle_data(payload)

    device = ActivatedKnownId()
    _, _, keys = await run_flow(device)
    assert keys.device_id == known_id
    assert keys.token == device.token


async def test_registration_tolerates_a_replayed_pubkey_announcement() -> None:
    class EchoingPubkeyAnnounce(FakeDevice):
        def __init__(self) -> None:
            super().__init__()
            self.echoed = False

        def handle_data(self, payload: bytes) -> None:
            if payload == bytes.fromhex("000000030400") and not self.echoed:
                self.echoed = True
                self.data(payload)  # a spurious retransmit of its own announcement
            super().handle_data(payload)

    device = EchoingPubkeyAnnounce()
    _, _, keys = await run_flow(device)
    assert keys.token == device.token


async def test_registration_rejects_a_device_public_key_off_the_curve() -> None:
    class GarbledPublicKey(FakeDevice):
        def collect_public_key(self, index: int, body: bytes) -> None:
            if index == 1:
                self.client_public = bytearray(b"\x04")
            self.client_public += body
            if index != 4:
                return
            self.phase = "sent_public_key"
            # (0, 0) is not a point on SECP256R1; from_encoded_point must reject it.
            for chunk in miauth.chunks(bytes(64)):
                self.data(chunk)

    link = FakeLink(GarbledPublicKey())
    auth = MiAuth(link)  # ty: ignore[invalid-argument-type]
    await auth.open()
    with pytest.raises(ActivationError, match="unusable public key"):
        await auth.register(timeout=5.0)


async def test_registration_logs_and_continues_after_a_device_timeout_notice(
    caplog: pytest.LogCaptureFixture,
) -> None:
    class TimingOutOnce(FakeDevice):
        def handle_control(self, payload: bytes) -> None:
            if payload.hex() == "a2000000":
                self.data(bytes.fromhex("000001050100"))  # spurious device timeout
            super().handle_control(payload)

    device = TimingOutOnce()
    _, _, keys = await run_flow(device)
    assert keys.token == device.token
    assert "device reported a timeout during registration" in caplog.text


async def test_registration_ignores_an_unrecognised_data_message(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG, logger="mjwsd05ctl.miauth")

    class SendingGarbage(FakeDevice):
        def handle_control(self, payload: bytes) -> None:
            if payload.hex() == "a2000000":
                self.data(b"\xff\xff\xff\xff")  # meaningless in any registration state
            super().handle_control(payload)

    device = SendingGarbage()
    _, _, keys = await run_flow(device)
    assert keys.token == device.token
    assert "unhandled registration message ffffffff" in caplog.text


async def test_registration_ignores_a_malformed_short_chunk_mid_key_exchange() -> None:
    class GlitchingDuringKeyExchange(FakeDevice):
        def collect_public_key(self, index: int, body: bytes) -> None:
            if index == 1:
                self.data(b"\x09")  # too short to carry a two-byte chunk header
            super().collect_public_key(index, body)

    device = GlitchingDuringKeyExchange()
    _, _, keys = await run_flow(device)
    assert keys.token == device.token


def test_public_key_bytes_requires_a_generated_keypair() -> None:
    auth = MiAuth(FakeLink(FakeDevice()))  # ty: ignore[invalid-argument-type]
    with pytest.raises(ActivationError, match="no key pair has been generated"):
        auth._public_key_bytes()


def test_derive_requires_a_generated_keypair() -> None:
    auth = MiAuth(FakeLink(FakeDevice()))  # ty: ignore[invalid-argument-type]
    with pytest.raises(ActivationError, match="no key pair has been generated"):
        auth._derive(bytes(65))
