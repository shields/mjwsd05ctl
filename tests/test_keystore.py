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

import json
import stat
from pathlib import Path

import pytest

from mjwsd05ctl import keystore
from mjwsd05ctl.errors import Error
from mjwsd05ctl.keystore import Keystore
from mjwsd05ctl.miauth import MiKeys

KEYS = MiKeys(token=bytes(range(12)), bindkey=bytes(range(16)), device_id=b"\x00abc")


def test_keys_round_trip(tmp_path: Path) -> None:
    store = Keystore(tmp_path / "sub" / "keys.json")
    store.put("a4:c1:38:11:22:33", KEYS)
    loaded = store.get("A4:C1:38:11:22:33")
    assert loaded == KEYS


def test_addresses_are_matched_regardless_of_case(tmp_path: Path) -> None:
    store = Keystore(tmp_path / "keys.json")
    store.put("A4:C1:38:AA:BB:CC", KEYS)
    assert store.get("a4:c1:38:aa:bb:cc") == KEYS


def test_addresses_with_surrounding_whitespace_are_matched(tmp_path: Path) -> None:
    # A pasted or scanned address can carry leading/trailing whitespace (a
    # trailing newline, in particular); it must still normalise to the same
    # key as the clean address it was stored under.
    store = Keystore(tmp_path / "keys.json")
    store.put("A4:C1:38:AA:BB:CC", KEYS)
    assert store.get("  a4:c1:38:aa:bb:cc\n") == KEYS


def test_a_missing_store_is_empty_not_an_error(tmp_path: Path) -> None:
    assert Keystore(tmp_path / "absent.json").load() == {}
    assert Keystore(tmp_path / "absent.json").get("A4:C1:38:11:22:33") is None


def test_the_file_is_readable_only_by_its_owner(tmp_path: Path) -> None:
    path = tmp_path / "keys.json"
    Keystore(path).put("A4:C1:38:11:22:33", KEYS)
    # Literal 0o600, not keystore.FILE_MODE: the token and bind key are secrets,
    # so the required mode is pinned here rather than recomputed from the very
    # constant a mutation of FILE_MODE would change.
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_the_parent_directory_is_accessible_only_by_its_owner(tmp_path: Path) -> None:
    path = tmp_path / "sub" / "keys.json"
    Keystore(path).put("A4:C1:38:11:22:33", KEYS)
    # Literal 0o700, not keystore.DIR_MODE: the directory lists which devices
    # have stored key material, so it is owner-only too.
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


def test_several_devices_coexist(tmp_path: Path) -> None:
    store = Keystore(tmp_path / "keys.json")
    other = MiKeys(token=bytes(12), bindkey=bytes(16), device_id=b"")
    store.put("A4:C1:38:00:00:01", KEYS)
    store.put("A4:C1:38:00:00:02", other)
    assert set(store.load()) == {"A4:C1:38:00:00:01", "A4:C1:38:00:00:02"}


def test_addresses_are_normalised_when_read_from_disk(tmp_path: Path) -> None:
    # A hand-edited or foreign-tool-written store might not have the address
    # key upper-cased already; load() must still normalise it so get() (which
    # always looks up an upper-cased key) can find it.
    path = tmp_path / "keys.json"
    path.write_text(
        json.dumps(
            {
                "a4:c1:38:11:22:33": {
                    "token": KEYS.token.hex(),
                    "bindkey": KEYS.bindkey.hex(),
                    "device_id": KEYS.device_id.hex(),
                }
            }
        )
    )
    assert set(Keystore(path).load()) == {"A4:C1:38:11:22:33"}


def test_a_missing_device_id_defaults_to_empty(tmp_path: Path) -> None:
    path = tmp_path / "keys.json"
    path.write_text(
        json.dumps(
            {
                "A4:C1:38:11:22:33": {
                    "token": KEYS.token.hex(),
                    "bindkey": KEYS.bindkey.hex(),
                }
            }
        )
    )
    loaded = Keystore(path).load()
    assert loaded["A4:C1:38:11:22:33"].device_id == b""


def test_overwriting_with_a_shorter_entry_leaves_no_trailing_garbage(
    tmp_path: Path,
) -> None:
    # put() must truncate the file, not just seek to the start and overwrite:
    # a shorter payload than what was previously on disk would otherwise leave
    # stale bytes past the new JSON object.
    path = tmp_path / "keys.json"
    long_keys = MiKeys(token=bytes(12), bindkey=bytes(16), device_id=bytes(64))
    short_keys = MiKeys(token=bytes(12), bindkey=bytes(16), device_id=b"")
    store = Keystore(path)
    store.put("A4:C1:38:11:22:33", long_keys)
    store.put("A4:C1:38:11:22:33", short_keys)
    parsed = json.loads(path.read_text())  # raises if trailing garbage remains
    assert parsed == {
        "A4:C1:38:11:22:33": {
            "token": short_keys.token.hex(),
            "bindkey": short_keys.bindkey.hex(),
            "device_id": "",
        }
    }


def test_the_file_ends_with_a_trailing_newline(tmp_path: Path) -> None:
    path = tmp_path / "keys.json"
    Keystore(path).put("A4:C1:38:11:22:33", KEYS)
    assert path.read_text().endswith("\n")


def test_bindkeys_are_exposed_for_decoding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "keys.json"
    Keystore(path).put("A4:C1:38:11:22:33", KEYS)
    monkeypatch.setenv(keystore.ENV_VAR, str(path))
    assert keystore.bindkeys() == {"A4:C1:38:11:22:33": KEYS.bindkey}


def test_a_damaged_entry_is_skipped_not_fatal(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "keys.json"
    path.write_text(
        json.dumps(
            {
                "A4:C1:38:00:00:01": {"token": "00", "bindkey": "00"},
                "A4:C1:38:00:00:02": {
                    "token": KEYS.token.hex(),
                    "bindkey": KEYS.bindkey.hex(),
                    "device_id": "",
                },
            }
        )
    )
    loaded = Keystore(path).load()
    assert set(loaded) == {"A4:C1:38:00:00:02"}
    assert "unusable key store entry" in caplog.text


def test_unreadable_json_is_an_error(tmp_path: Path) -> None:
    path = tmp_path / "keys.json"
    path.write_text("this is not JSON")
    with pytest.raises(Error, match="cannot read key store"):
        Keystore(path).load()


def test_the_environment_overrides_the_default_location(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv(keystore.ENV_VAR, str(tmp_path / "elsewhere.json"))
    assert keystore.default_path() == tmp_path / "elsewhere.json"


def test_the_default_location_follows_xdg(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv(keystore.ENV_VAR, raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    assert keystore.default_path() == tmp_path / "mjwsd05ctl" / "keys.json"


def test_the_default_location_falls_back_to_home_when_xdg_is_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The `Path(...) if config else Path.home() / ".config"` expression lives
    # on one line, so line/branch coverage can be 100% green even though no
    # test ever forces the `else` arm: both arms fall through to the same
    # next line, leaving coverage.py nothing to flag as partial.
    monkeypatch.delenv(keystore.ENV_VAR, raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    expected = Path.home() / ".config" / "mjwsd05ctl" / "keys.json"
    assert keystore.default_path() == expected


def test_loose_permissions_on_an_existing_file_are_tightened(tmp_path: Path) -> None:
    path = tmp_path / "keys.json"
    path.write_text("{}")
    path.chmod(0o644)
    Keystore(path).put("A4:C1:38:11:22:33", KEYS)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_loose_permissions_on_an_existing_directory_are_tightened(
    tmp_path: Path,
) -> None:
    # mkdir's mode argument (and O_CREAT's, for the file) is ignored when the
    # target already exists, which is why _write chmods the directory
    # explicitly after mkdir; a pre-existing, group/world-readable directory
    # must still end up owner-only.
    sub = tmp_path / "sub"
    sub.mkdir()
    sub.chmod(0o755)
    Keystore(sub / "keys.json").put("A4:C1:38:11:22:33", KEYS)
    assert stat.S_IMODE(sub.stat().st_mode) == 0o700


def test_open_uses_the_caller_supplied_path_over_the_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Point the default location somewhere else entirely, so that if
    # Keystore.open() ever ignored the explicit path in favour of the
    # default, bindkeys() would read an empty (nonexistent) store instead.
    monkeypatch.delenv(keystore.ENV_VAR, raising=False)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "elsewhere"))
    path = tmp_path / "explicit.json"
    Keystore(path).put("A4:C1:38:11:22:33", KEYS)
    assert keystore.bindkeys(path) == {"A4:C1:38:11:22:33": KEYS.bindkey}


def test_a_write_that_the_filesystem_refuses_is_a_keystore_error(
    tmp_path: Path,
) -> None:
    # No write permission on the parent, so creating the "sub" directory
    # underneath it fails and _write's mkdir raises OSError.
    locked = tmp_path / "locked"
    locked.mkdir(mode=0o500)
    try:
        path = locked / "sub" / "keys.json"
        with pytest.raises(Error, match="cannot write key store"):
            Keystore(path).put("A4:C1:38:11:22:33", KEYS)
    finally:
        locked.chmod(0o700)
