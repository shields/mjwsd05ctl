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

"""GATT identifiers and wire protocol constants.

Sourced from the pvvx firmware (`src/cmd_parser.h`, `src/app_config.h`) and from
`TelinkMiFlasher.html`, which is the reference implementation for the Xiaomi
activation and Telink update protocols.
"""

from enum import IntEnum


def uuid16(value: int) -> str:
    """Expand a 16-bit Bluetooth SIG identifier to its full 128-bit form."""
    return f"0000{value:04x}-0000-1000-8000-00805f9b34fb"


# Xiaomi "mible" authentication service, present on stock firmware.
MI_AUTH_SERVICE = uuid16(0xFE95)
MI_AUTH_CONTROL_CHAR = uuid16(0x0010)  # enc_10 in TelinkMiFlasher.html
MI_AUTH_DATA_CHAR = uuid16(0x0019)  # enc_19

# Xiaomi vendor service, present on stock firmware.
MI_MAIN_SERVICE = "ebe0ccb0-7a0a-4b0c-8a1a-6ff2997da3a6"
MI_SPEED_CHAR = "ebe0ccd8-7a0a-4b0c-8a1a-6ff2997da3a6"
MI_SENSOR_CHAR = "ebe0ccc1-7a0a-4b0c-8a1a-6ff2997da3a6"
MI_CLOCK_CHAR = "ebe0ccb7-7a0a-4b0c-8a1a-6ff2997da3a6"

# Telink over-the-air update service.
OTA_SERVICE = "00010203-0405-0607-0809-0a0b0c0d1912"
OTA_CHAR = "00010203-0405-0607-0809-0a0b0c0d2b12"

# pvvx custom firmware configuration service.
CUSTOM_SERVICE = uuid16(0x1F10)
CUSTOM_CHAR = uuid16(0x1F1F)

# Device Information Service.
DIS_SERVICE = uuid16(0x180A)
DIS_FIRMWARE_REVISION_CHAR = uuid16(0x2A26)
DIS_HARDWARE_REVISION_CHAR = uuid16(0x2A27)
DIS_SOFTWARE_REVISION_CHAR = uuid16(0x2A28)

# Service data UUIDs carrying sensor measurements in advertisements.
BTHOME_SERVICE = uuid16(0xFCD2)
ATC_SERVICE = uuid16(0x181A)
MI_BEACON_SERVICE = uuid16(0xFE95)

DEVICE_NAME = "MJWSD05MMC"

# Hardware identifiers, from DEVICE_MJWSD05MMC{,_EN} in the firmware sources.
# The two variants differ only in their LCD, but need different images.
HW_ID_CH = 9
HW_ID_EN = 12

# The Chinese and international units are told apart by their Device Information
# Service firmware revision string (TelinkMiFlasher.html:2098).
FIRMWARE_REVISION_EN = "0005"

# Default image names in the pvvx release tree, keyed by hardware id.
FIRMWARE_NAMES = {HW_ID_CH: "BTH_v58.bin", HW_ID_EN: "BTE_v58.bin"}

# `VERSION` in src/app_config.h, BCD: 0x58 is firmware 5.8.
CONFIG_VERSION = 0x58

# Stock MJWSD05MMC accepts an image up to 208 KiB; a device already running
# custom firmware reports its own limit, defaulting to the 128 KiB OTA slot.
MAX_BLE_OTA_SIZE = 0x20000
MAX_EXT_OTA_SIZE = 0x34000


class CommandId(IntEnum):
    """Opcodes for the custom firmware's 0x1F1F characteristic.

    The full list lives in `src/cmd_parser.h`; this covers what we use.
    """

    DEV_ID = 0x00
    DNAME = 0x01
    DEV_MAC = 0x10
    MI_TBIND = 0x12
    MI_KALL = 0x15
    MI_REST = 0x16
    MI_CLR = 0x17
    BKEY = 0x18
    COMFORT = 0x20
    UTC_TIME = 0x23
    MEASURE = 0x33
    CFG = 0x55
    CFG_DEF = 0x56
    LCD_DUMP = 0x60
    PINCODE = 0x70
    MTU = 0x71
    REBOOT = 0x72
    SET_OTA = 0x73


class AdvertisingType(IntEnum):
    """`cfg.flg.advertising_type`."""

    ATC1441 = 0
    PVVX = 1
    MI = 2
    BTHOME = 3


class ScreenType(IntEnum):
    """`cfg.flg2.screen_type` on the MJWSD05MMC."""

    TIME = 0
    TEMPERATURE = 1
    HUMIDITY = 2
    BATTERY_PERCENT = 3
    BATTERY_VOLTAGE = 4
    EXTERNAL = 5


class MiStatus(IntEnum):
    """Status codes notified on the Mi authentication control characteristic."""

    REG_SUCCESS = 0x11
    REG_FAILED = 0x12
    REG_VERIFY_SUCC = 0x13
    REG_VERIFY_FAIL = 0x14
    LOG_SUCCESS = 0x21
    LOG_INVALID_LTMK = 0x22
    LOG_FAILED = 0x23
    ERR_NOT_REGISTERED = 0xE0
    ERR_REGISTERED = 0xE1
    ERR_REPEAT_LOGIN = 0xE2
    ERR_INVALID_OOB = 0xE3


MI_STATUS_TEXT = {
    MiStatus.REG_SUCCESS: "registration successful",
    MiStatus.REG_FAILED: "registration failed",
    MiStatus.REG_VERIFY_SUCC: "registration verify successful",
    MiStatus.REG_VERIFY_FAIL: "registration verify failed",
    MiStatus.LOG_SUCCESS: "login successful",
    MiStatus.LOG_INVALID_LTMK: "login rejected: invalid LTMK",
    MiStatus.LOG_FAILED: "login failed",
    MiStatus.ERR_NOT_REGISTERED: "device is not registered",
    MiStatus.ERR_REGISTERED: "device is already registered",
    MiStatus.ERR_REPEAT_LOGIN: "already logged in",
    MiStatus.ERR_INVALID_OOB: "invalid out-of-band data",
}

# Control-characteristic commands (little-endian u32 written to enc_10).
MI_CMD_REGISTER_START = bytes.fromhex("a2000000")
MI_CMD_REGISTER_BEGIN = bytes.fromhex("15000000")
MI_CMD_REGISTER_VERIFY = bytes.fromhex("13000000")
MI_CMD_LOGIN_START = bytes.fromhex("24000000")

# Key derivation parameters. `MI_DID_NONCE` and `MI_DID_AAD` ("devID") are fixed
# by the protocol, not secret.
MI_SETUP_INFO = b"mible-setup-info"
MI_LOGIN_INFO = b"mible-login-info"
MI_DID_NONCE = bytes.fromhex("101112131415161718191A1B")
MI_DID_AAD = b"devID"
MI_DID_MAC_LEN = 4

MI_TOKEN_LEN = 12
MI_BINDKEY_LEN = 16
MI_RANDOM_LEN = 16

# Writing this to the Xiaomi vendor "speed" characteristic asks the device for a
# shorter connection interval, which roughly halves upload time.
MI_SPEED_FAST = bytes.fromhex("1e0000")

# Telink OTA framing.
OTA_BLOCK_SIZE = 16
OTA_FRAME_SIZE = 20  # sequence number, payload, CRC
OTA_START_COMMANDS = (bytes.fromhex("00ff"), bytes.fromhex("01ff"))
OTA_END_COMMAND = bytes.fromhex("02ff")
OTA_STATUS_INTERVAL = 8  # poll the status byte after every Nth block

OTA_ERRORS = (
    "success",
    "lost one or more packets",
    "CRC error in data",
    "error writing data to flash",
    "lost last one or more packets",
    "timeout",
    "firmware CRC check failed",
)

# Telink image header, validated before we send anything.
TELINK_MAGIC = 0x544C4E4B  # "TLNK"
TELINK_MAGIC_OFFSET = 0x08
TELINK_HSIZE_OFFSET = 0x18
TELINK_MIN_SIZE = 1024
