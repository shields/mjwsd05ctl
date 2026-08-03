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

"""Xiaomi "mible" registration and login.

Registration is an ECDH exchange with the device itself: no Xiaomi account and
no network access are involved. It yields a token and a bind key, which are what
Mi Home would otherwise hold, and which the pvvx firmware reuses to sign
encrypted advertisements. Registering here replaces any existing registration,
so a device already paired with Mi Home has to be added there again.

The message sequence is transcribed from `TelinkMiFlasher.html`, the only
description of this protocol that exists; state numbers below match the `state`
variable there so the two can be compared.
"""

import asyncio
import hashlib
import hmac
import logging
import secrets
import string
from dataclasses import dataclass
from enum import IntEnum
from typing import TYPE_CHECKING

from Crypto.Cipher import AES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .constants import (
    MI_AUTH_CONTROL_CHAR,
    MI_AUTH_DATA_CHAR,
    MI_BINDKEY_LEN,
    MI_CMD_LOGIN_START,
    MI_CMD_REGISTER_BEGIN,
    MI_CMD_REGISTER_START,
    MI_CMD_REGISTER_VERIFY,
    MI_DID_AAD,
    MI_DID_MAC_LEN,
    MI_DID_NONCE,
    MI_LOGIN_INFO,
    MI_RANDOM_LEN,
    MI_SETUP_INFO,
    MI_STATUS_TEXT,
    MI_TOKEN_LEN,
    MiStatus,
)
from .errors import ActivationError

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from .transport import Link

log = logging.getLogger(__name__)

REGISTER_TIMEOUT = 60.0
LOGIN_TIMEOUT = 60.0

type _Handler = Callable[[bytes], Awaitable[None]]

# The device pauses between accepting a command and being ready for the next.
SETTLE = 0.25

# Payloads are sent in chunks of at most 18 bytes behind a two-byte index.
CHUNK_SIZE = 18

# Control characteristic messages, and data characteristic messages that carry
# no payload. Named after their role rather than their bytes, which are opaque.
_ACK = bytes.fromhex("00000100")
_READY = bytes.fromhex("00000101")
_ACK_SHORT = bytes.fromhex("00000300")
_ANNOUNCE_PUBKEY = bytes.fromhex("000000030400")
_ANNOUNCE_DID = bytes.fromhex("000000000200")
_ANNOUNCE_LOGIN = bytes.fromhex("0000000b0100")
_ANNOUNCE_INFO_ONE = bytes.fromhex("0000000a0100")
_ANNOUNCE_INFO_TWO = bytes.fromhex("0000000a0200")
_NOT_ACTIVATED = bytes.fromhex("000000000100")
_ACTIVATED = bytes.fromhex("000000000200")
_RESTART_REGISTER = bytes.fromhex("010001000000")
_DEVICE_TIMEOUT = bytes.fromhex("000001050100")
_DEVICE_ID_PREFIX = bytes.fromhex("0000020001000000")
_RANDOM_EXCHANGE = bytes.fromhex("0000000d0100")
_INFO_EXCHANGE = bytes.fromhex("0000000c0200")
_SHORT_RANDOM_PREFIX = bytes.fromhex("0000020d")
_SHORT_INFO_PREFIX = bytes.fromhex("0000020c")
_RELOGIN_PREFIX = bytes.fromhex("000004")
_RELOGIN_REPLY = bytes.fromhex("000005")

# Chunk indices, sent as the first byte of a two-byte header.
_CHUNK_HEADER_LEN = 2
_CHUNK_FIRST = 1
_CHUNK_SECOND = 2
_CHUNK_LAST_PUBKEY = 4

# A restart request is a three-byte prefix plus the reason.
_RELOGIN_MIN_LEN = 4
_RELOGIN_REASON_LOGIN = 1

# The device prepends a four-byte header to the identifier it already holds.
_KNOWN_ID_HEADER_LEN = 4

_TERMINAL_SUCCESS = frozenset(
    {MiStatus.REG_SUCCESS, MiStatus.LOG_SUCCESS, MiStatus.ERR_REPEAT_LOGIN}
)
_TERMINAL_FAILURE = frozenset(
    {
        MiStatus.REG_FAILED,
        MiStatus.REG_VERIFY_FAIL,
        MiStatus.LOG_INVALID_LTMK,
        MiStatus.LOG_FAILED,
        MiStatus.ERR_NOT_REGISTERED,
        MiStatus.ERR_REGISTERED,
        MiStatus.ERR_INVALID_OOB,
    }
)


class _Register(IntEnum):
    """Registration progress, matching `state` in the reference flasher."""

    IDLE = 0
    STARTED = 1
    KEY_EXCHANGE = 2
    SENDING_DID = 3


class _Login(IntEnum):
    """Login progress. Values 12-14 are the single-message variant."""

    IDLE = 0
    SENT_RANDOM = 1
    ACK_RANDOM = 2
    GOT_RANDOM = 3
    ACK_INFO = 4
    INFO_PART_ONE = 5
    INFO_COMPLETE = 6
    SENT_INFO = 7
    SHORT_GOT_RANDOM = 12
    SHORT_GOT_INFO = 13
    SHORT_SENT_INFO = 14


@dataclass(frozen=True, slots=True)
class MiKeys:
    """What registration produces, and what login needs."""

    token: bytes
    bindkey: bytes
    device_id: bytes

    def __post_init__(self) -> None:
        if len(self.token) != MI_TOKEN_LEN:
            msg = f"token must be {MI_TOKEN_LEN} bytes, got {len(self.token)}"
            raise ActivationError(msg)
        if len(self.bindkey) != MI_BINDKEY_LEN:
            msg = f"bind key must be {MI_BINDKEY_LEN} bytes, got {len(self.bindkey)}"
            raise ActivationError(msg)


def generate_device_id() -> bytes:
    """Build a device identifier in the format Mi Home assigns.

    A NUL, the fixed string "blt.3.129v", six random alphanumerics, then "g00".
    """
    alphabet = string.ascii_letters + string.digits
    suffix = "".join(secrets.choice(alphabet) for _ in range(6))
    return b"\x00blt.3.129v" + suffix.encode("ascii") + b"g00"


def derive_setup_keys(shared_secret: bytes) -> tuple[bytes, bytes, bytes]:
    """Split the ECDH secret into the token, bind key, and DID wrapping key."""
    derived = HKDF(
        algorithm=hashes.SHA256(), length=64, salt=None, info=MI_SETUP_INFO
    ).derive(shared_secret)
    return derived[0:12], derived[12:28], derived[28:44]


def wrap_device_id(key: bytes, device_id: bytes) -> bytes:
    """AES-CCM the device identifier under the derived key, tag appended."""
    cipher = AES.new(key, AES.MODE_CCM, nonce=MI_DID_NONCE, mac_len=MI_DID_MAC_LEN)
    cipher.update(MI_DID_AAD)
    ciphertext, tag = cipher.encrypt_and_digest(device_id)
    return ciphertext + tag


def derive_login_proofs(
    token: bytes, ours: bytes, theirs: bytes
) -> tuple[bytes, bytes]:
    """Compute the proof we expect from the device, and the one we send."""
    derived = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=ours + theirs,
        info=MI_LOGIN_INFO,
    ).derive(token)
    expected = hmac.new(derived[0:16], theirs + ours, hashlib.sha256).digest()
    ours_proof = hmac.new(derived[16:32], ours + theirs, hashlib.sha256).digest()
    return expected, ours_proof


def chunks(payload: bytes, size: int = CHUNK_SIZE) -> list[bytes]:
    """Split a payload into indexed chunks as the protocol frames them."""
    parts = [payload[i : i + size] for i in range(0, len(payload), size)]
    return [bytes([index, 0]) + part for index, part in enumerate(parts, start=1)]


class MiAuth:
    """Drives registration and login over the two authentication characteristics."""

    def __init__(self, link: Link) -> None:
        self._link = link
        self._events: asyncio.Queue[tuple[str, bytes]] | None = None
        self._state: int = _Register.IDLE
        self._private_key: ec.EllipticCurvePrivateKey | None = None
        self._device_public = bytearray()
        self._device_id = b""
        self._known_id = b""
        self._activated = False
        self._wrapped_did = b""
        self._token = b""
        self._bindkey = b""
        self._random = b""
        self._peer_random = b""
        self._expected_proof = b""
        self._our_proof = b""
        self._received_proof = bytearray()

    async def open(self) -> None:
        """Subscribe to both authentication characteristics."""
        self._events = await self._link.subscribe_tagged(
            (MI_AUTH_CONTROL_CHAR, MI_AUTH_DATA_CHAR)
        )

    async def activate(self) -> MiKeys:
        """Register, then log in with the freshly derived token."""
        keys = await self.register()
        await self.login(keys.token)
        return keys

    async def register(self, timeout: float = REGISTER_TIMEOUT) -> MiKeys:
        """Run the ECDH registration exchange and return the derived keys."""
        self._state = _Register.IDLE
        self._activated = False
        self._device_id = generate_device_id()
        self._device_public = bytearray()
        self._known_id = b""
        self._new_keypair()

        log.info("registering; this replaces any existing Mi Home pairing")
        await self._control(MI_CMD_REGISTER_START)
        await self._pump(self._handle_register, timeout=timeout)
        return MiKeys(
            token=self._token, bindkey=self._bindkey, device_id=self._device_id
        )

    async def login(self, token: bytes, timeout: float = LOGIN_TIMEOUT) -> None:
        """Prove knowledge of the token to unlock the device."""
        if len(token) != MI_TOKEN_LEN:
            msg = f"token must be {MI_TOKEN_LEN} bytes, got {len(token)}"
            raise ActivationError(msg)
        self._token = token
        await self._begin_login()
        await self._pump(self._handle_login, timeout=timeout)

    async def _begin_login(self) -> None:
        self._state = _Login.IDLE
        self._random = secrets.token_bytes(MI_RANDOM_LEN)
        self._received_proof = bytearray()
        await self._control(MI_CMD_LOGIN_START)
        await self._data(_ANNOUNCE_LOGIN)

    async def _pump(self, handler: _Handler, *, timeout: float) -> None:
        """Dispatch notifications until the device reports success or failure."""
        if self._events is None:
            msg = "MiAuth.open() must be called before registering or logging in"
            raise ActivationError(msg)

        try:
            async with asyncio.timeout(timeout):
                while True:
                    source, value = await self._events.get()
                    if source == MI_AUTH_CONTROL_CHAR:
                        if self._handle_status(value):
                            return
                        continue
                    if await self._handle_common(value):
                        continue
                    await handler(value)
        except TimeoutError:
            msg = f"device did not respond within {timeout:g}s"
            raise ActivationError(msg) from None

    def _handle_status(self, value: bytes) -> bool:
        """Interpret a control characteristic notification. True means done."""
        if not value:
            return False
        try:
            status = MiStatus(value[0])
        except ValueError:
            log.debug("unrecognised status %s", value.hex())
            return False

        text = MI_STATUS_TEXT[status]
        if status in _TERMINAL_FAILURE:
            raise ActivationError(text)
        if status in _TERMINAL_SUCCESS:
            log.info("%s", text)
            return True
        log.debug("%s", text)
        return False

    async def _handle_common(self, value: bytes) -> bool:
        """Handle the device asking us to restart, in either mode."""
        if not value.startswith(_RELOGIN_PREFIX) or len(value) < _RELOGIN_MIN_LEN:
            return False
        await self._data(_RELOGIN_REPLY + value[3:])
        if value[3] == _RELOGIN_REASON_LOGIN:
            await asyncio.sleep(SETTLE)
            await self._begin_login()
        return True

    async def _handle_register(self, value: bytes) -> None:
        state = self._state
        if value.startswith(_DEVICE_ID_PREFIX):
            self._device_id = value[len(_DEVICE_ID_PREFIX) :]
            await self._restart_register()
        elif value == _NOT_ACTIVATED:
            self._activated = False
            await self._data(_READY)
        elif value == _ACTIVATED:
            self._activated = True
            await self._data(_READY)
        elif (
            self._activated
            and state == _Register.IDLE
            and _index(value) == _CHUNK_FIRST
        ):
            self._known_id = value[2:]
        elif (
            self._activated
            and state == _Register.IDLE
            and _index(value) == _CHUNK_SECOND
        ):
            self._known_id += value[2:]
            self._device_id = self._known_id[_KNOWN_ID_HEADER_LEN:]
            await self._restart_register()
        elif value == _RESTART_REGISTER:
            await self._restart_register()
        elif state == _Register.STARTED and value == _READY:
            self._state = _Register.KEY_EXCHANGE
            await self._send_public_key()
        elif value == _ANNOUNCE_PUBKEY:
            await self._data(_READY)
        elif (
            state == _Register.KEY_EXCHANGE and 1 <= _index(value) <= _CHUNK_LAST_PUBKEY
        ):
            await self._collect_public_key(value)
        elif state == _Register.KEY_EXCHANGE and value == _READY:
            self._state = _Register.SENDING_DID
            for chunk in chunks(self._wrapped_did):
                await self._data(chunk)
        elif state == _Register.SENDING_DID and value == _ACK:
            self._state = _Register.IDLE
            await self._control(MI_CMD_REGISTER_VERIFY)
        elif value == _DEVICE_TIMEOUT:
            log.warning("device reported a timeout during registration")
        else:
            log.debug("unhandled registration message %s", value.hex())

    async def _handle_login(self, value: bytes) -> None:
        state = self._state
        if state == _Login.IDLE and value == _READY:
            self._state = _Login.SENT_RANDOM
            await self._data(bytes([_CHUNK_FIRST, 0]) + self._random)
        elif state == _Login.SENT_RANDOM and value == _RANDOM_EXCHANGE:
            self._state = _Login.ACK_RANDOM
            await self._data(_READY)
        elif state == _Login.SENT_RANDOM and value.startswith(_SHORT_RANDOM_PREFIX):
            self._state = _Login.SHORT_GOT_RANDOM
            self._accept_peer_random(value[len(_SHORT_RANDOM_PREFIX) :])
            await self._data(_ACK_SHORT)
        elif state == _Login.ACK_RANDOM and _index(value) == 1:
            self._state = _Login.GOT_RANDOM
            self._accept_peer_random(value[2:])
            await self._data(_ACK)
        elif state == _Login.GOT_RANDOM and value == _INFO_EXCHANGE:
            self._state = _Login.ACK_INFO
            await self._data(_READY)
        elif state == _Login.SHORT_GOT_RANDOM and value.startswith(_SHORT_INFO_PREFIX):
            self._state = _Login.SHORT_GOT_INFO
            self._received_proof = bytearray(value[len(_SHORT_INFO_PREFIX) :])
            await self._data(_ACK_SHORT)
            self._check_proof()
            await self._data(_ANNOUNCE_INFO_ONE)
        elif state == _Login.ACK_INFO and _index(value) == _CHUNK_FIRST:
            self._state = _Login.INFO_PART_ONE
            self._received_proof = bytearray(value[2:])
        elif state == _Login.INFO_PART_ONE and _index(value) == _CHUNK_SECOND:
            self._state = _Login.INFO_COMPLETE
            self._received_proof += value[2:]
            self._check_proof()
            await self._data(_ACK)
            await self._data(_ANNOUNCE_INFO_TWO)
        elif state == _Login.INFO_COMPLETE and value == _READY:
            self._state = _Login.SENT_INFO
            for chunk in chunks(self._our_proof):
                await self._data(chunk)
        elif state == _Login.SHORT_GOT_INFO and value == _READY:
            self._state = _Login.SHORT_SENT_INFO
            await self._data(bytes([_CHUNK_FIRST, 0]) + self._our_proof)
        elif state == _Login.SHORT_SENT_INFO and value == _ACK:
            self._state = _Login.IDLE
            log.debug("proof sent; awaiting the device's verdict")
        else:
            log.debug("unhandled login message %s", value.hex())

    async def _restart_register(self) -> None:
        await self._data(_ACK)
        await asyncio.sleep(SETTLE)
        self._state = _Register.STARTED
        self._new_keypair()
        await self._control(MI_CMD_REGISTER_BEGIN)
        await self._data(_ANNOUNCE_PUBKEY)

    def _new_keypair(self) -> None:
        self._private_key = ec.generate_private_key(ec.SECP256R1())

    def _public_key_bytes(self) -> bytes:
        if self._private_key is None:
            msg = "no key pair has been generated"
            raise ActivationError(msg)
        return self._private_key.public_key().public_bytes(
            Encoding.X962, PublicFormat.UncompressedPoint
        )

    async def _send_public_key(self) -> None:
        # Drop the leading 0x04 uncompressed-point marker; the device assumes it.
        body = self._public_key_bytes()[1:]
        for chunk in chunks(body):
            await self._data(chunk)

    async def _collect_public_key(self, value: bytes) -> None:
        if _index(value) == _CHUNK_FIRST:
            self._device_public = bytearray(b"\x04")
        self._device_public += value[2:]
        if _index(value) != _CHUNK_LAST_PUBKEY:
            return
        await self._data(_ACK)
        self._derive(bytes(self._device_public))
        await self._data(_ANNOUNCE_DID)

    def _derive(self, device_public: bytes) -> None:
        if self._private_key is None:
            msg = "no key pair has been generated"
            raise ActivationError(msg)
        try:
            peer = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), device_public
            )
        except ValueError as exc:
            msg = f"device sent an unusable public key: {exc}"
            raise ActivationError(msg) from exc

        shared = self._private_key.exchange(ec.ECDH(), peer)
        self._token, self._bindkey, wrapping_key = derive_setup_keys(shared)
        self._wrapped_did = wrap_device_id(wrapping_key, self._device_id)

    def _accept_peer_random(self, value: bytes) -> None:
        self._peer_random = value
        self._expected_proof, self._our_proof = derive_login_proofs(
            self._token, self._random, self._peer_random
        )

    def _check_proof(self) -> None:
        received = bytes(self._received_proof)
        if hmac.compare_digest(received, self._expected_proof):
            log.debug("device proof verified")
            return
        # The reference flasher only logs this, but a device that cannot prove
        # it holds the token is not one we should keep talking to.
        msg = "device failed to prove it holds the token"
        raise ActivationError(msg)

    async def _control(self, data: bytes) -> None:
        await self._link.write(MI_AUTH_CONTROL_CHAR, data)

    async def _data(self, data: bytes) -> None:
        await self._link.write(MI_AUTH_DATA_CHAR, data)


def _index(value: bytes) -> int:
    """The chunk index of a data message, or 0 if it is not a chunk."""
    if len(value) < _CHUNK_HEADER_LEN or value[1] != 0:
        return 0
    return value[0]
