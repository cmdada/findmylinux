#!/usr/bin/env python3
"""Advertise this machine on Apple's Find My network as if it's an apple accessory

The accessory public key is split across the BLE advertising address (first six
bytes) and a manufacturer-specific payload that fills all 31 bytes of a legacy
advertisement. BlueZ's management API cannot express that packet:

  - `Add Advertising` reserves three bytes to insert its own Flags element, so
    it rejects a 31-byte payload (status 0x0d) and leaves no room for the 22
    key bytes the Find My element has to carry.
  - `Add Extended Advertising` accepts the payload but assigns its own
    non-resolvable address and emits extended PDUs, which Find My scanners
    ignore.

So the controller is driven directly over an HCI user channel, which is also
what OpenHaystack's ESP32 firmware does. That takes the adapter away from
bluetoothd for as long as this runs, don't use this if you need bluetooth headphones :)
"""

import argparse
import base64
import errno
import hashlib
import json
import logging
import os
import random
import secrets
import signal
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ROOT = Path(__file__).resolve().parent


def _data_dir():
    override = os.environ.get("FINDMYLINUX_DATA")
    if override:
        return Path(override)
    xdg = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return Path(xdg) / "findmylinux"


DATA_DIR = _data_dir()
KEYS_DIR = DATA_DIR / "keys"

APPLE_COMPANY_ID = b"\x4c\x00"
OFFLINE_FINDING_TYPE = 0x12

HCI_CHANNEL_USER = 1
HCI_COMMAND_PKT = 0x01
HCI_EVENT_PKT = 0x04
EVT_CMD_COMPLETE = 0x0E
EVT_CMD_STATUS = 0x0F

OP_RESET = 0x0C03
OP_LE_READ_LOCAL_FEATURES = 0x2003
OP_LE_SET_RANDOM_ADDRESS = 0x2005
OP_LE_SET_ADV_PARAMETERS = 0x2006
OP_LE_SET_ADV_DATA = 0x2008
OP_LE_SET_ADV_ENABLE = 0x200A
OP_LE_SET_EXT_ADV_SET_RANDOM_ADDR = 0x2035
OP_LE_SET_EXT_ADV_PARAMETERS = 0x2036
OP_LE_SET_EXT_ADV_DATA = 0x2037
OP_LE_SET_EXT_ADV_ENABLE = 0x2039

ADV_NONCONN_IND = 0x03
OWN_ADDR_RANDOM = 0x01

EXT_PROP_LEGACY_NONCONN = 0x0010
LE_FEATURE_EXT_ADVERTISING = (1, 0x10)


def derive_keypair():
    """Return (private_key, advertisement_key), both 28 bytes."""
    while True:
        priv_int = secrets.randbits(224)
        try:
            priv = ec.derive_private_key(priv_int, ec.SECP224R1())
        except ValueError:
            continue
        adv = priv.public_key().public_numbers().x.to_bytes(28, "big")
        hashed = base64.b64encode(hashlib.sha256(adv).digest()).decode()
        if "/" in hashed[:7]:
            continue
        return priv_int.to_bytes(28, "big"), adv


def cmd_keygen(args):
    priv, adv = derive_keypair()
    hashed = hashlib.sha256(adv).digest()

    priv_b64 = base64.b64encode(priv).decode()
    adv_b64 = base64.b64encode(adv).decode()
    hashed_b64 = base64.b64encode(hashed).decode()

    KEYS_DIR.mkdir(parents=True, mode=0o700, exist_ok=True)
    os.chmod(KEYS_DIR, 0o700)

    keyfile = KEYS_DIR / f"{args.name}.keys"
    if keyfile.exists() and not args.force:
        sys.exit(f"{keyfile} exists; refusing to overwrite without --force.\n"
                 "Regenerating discards every location report tied to the old key.")

    keyfile.write_text(
        f"Private key: {priv_b64}\n"
        f"Advertisement key: {adv_b64}\n"
        f"Hashed adv key: {hashed_b64}\n"
    )
    os.chmod(keyfile, 0o600)

    advfile = KEYS_DIR / f"{args.name}.adv"
    advfile.write_text(adv_b64 + "\n")
    os.chmod(advfile, 0o644)

    devices = KEYS_DIR / f"{args.name}_devices.json"
    devices.write_text(json.dumps([{
        "id": random.randrange(0, 10_000_000),
        "colorComponents": [0, 1, 0, 1],
        "name": args.name,
        "privateKey": priv_b64,
        "icon": "briefcase.fill",
        "isActive": True,
        "additionalKeys": [],
    }], indent=2) + "\n")
    os.chmod(devices, 0o600)

    addr, payload = advertisement(adv)
    print(f"wrote {keyfile}")
    print(f"      {advfile}")
    print(f"      {devices}")
    print()
    print(f"advertisement key : {adv_b64}")
    print(f"hashed adv key    : {hashed_b64}")
    print(f"BLE address       : {format_addr(addr)}")
    print(f"payload           : {payload.hex()}")


def load_adv_key(name):
    advfile = KEYS_DIR / f"{name}.adv"
    if not advfile.exists():
        sys.exit(f"{advfile} not found — run `findmylinux.py keygen` first.")
    adv = base64.b64decode(advfile.read_text().strip())
    if len(adv) != 28:
        sys.exit(f"{advfile}: expected a 28-byte advertisement key, got {len(adv)}")
    return adv


def advertisement(adv_key):
    """Build the (address, 31-byte AD payload) pair for an advertisement key."""
    addr = bytearray(adv_key[:6])
    addr[0] |= 0b11000000

    payload = bytearray(31)
    payload[0] = 0x1E
    payload[1] = 0xFF
    payload[2:4] = APPLE_COMPANY_ID
    payload[4] = OFFLINE_FINDING_TYPE
    payload[5] = 0x19
    payload[6] = 0x00
    payload[7:29] = adv_key[6:28]
    payload[29] = adv_key[0] >> 6
    payload[30] = 0x00

    return bytes(addr), bytes(payload)


def format_addr(addr):
    return ":".join(f"{b:02X}" for b in addr)


APPLE_EPOCH_OFFSET = 978307200

ANISETTE_URL = os.environ.get("FINDMYLINUX_ANISETTE", "http://127.0.0.1:6969")
APPLE_DATA_DIR = KEYS_DIR / "apple"

CONFIG_FILE = DATA_DIR / "config.json"
DEFAULT_INTERVAL = 600
DEFAULT_WINDOW = 60


def load_config():
    try:
        return json.loads(CONFIG_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def save_config(config):
    CONFIG_FILE.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2) + "\n")


def triangulate(fixes, window=DEFAULT_WINDOW):
    """Merge fixes whose timestamps fall within `window` seconds into one
    accuracy-weighted position. Apple returns several reports per sighting; a
    report with a tighter radius is trusted more (weight = 1/radius^2), and
    combining N of them shrinks the radius by about sqrt(N). Returns the merged
    fixes newest-first; window <= 0 disables merging."""
    if window <= 0:
        return sorted(fixes, reverse=True)
    clusters = []
    for fix in sorted(fixes, reverse=True):
        for cluster in clusters:
            if cluster[0] - fix[0] <= window:
                cluster[1].append(fix)
                break
        else:
            clusters.append((fix[0], [fix]))
    merged = []
    for newest, members in clusters:
        if len(members) == 1:
            merged.append(members[0])
            continue
        weights = [1.0 / max(1, acc) ** 2 for _, _, _, acc in members]
        total = sum(weights)
        lat = sum(w * m[1] for w, m in zip(weights, members)) / total
        lon = sum(w * m[2] for w, m in zip(weights, members)) / total
        avg_acc = sum(w * m[3] for w, m in zip(weights, members)) / total
        acc = max(1, round(avg_acc / len(members) ** 0.5))
        merged.append((newest, lat, lon, acc))
    merged.sort(reverse=True)
    return merged


def apple_account():
    import apple
    return apple.AppleAccount(ANISETTE_URL, APPLE_DATA_DIR)


def decrypt_report(payload, private_key):
    """Recover (timestamp, lat, lon, accuracy) from one encrypted report.

    The report is ECIES against the accessory key: an ephemeral P-224 public
    key, then AES-GCM under a key derived from the ECDH secret.
    """
    data = base64.b64decode(payload)
    if len(data) == 89:
        data = data[:4] + data[5:]
    if len(data) != 88:
        raise ValueError(f"unexpected report length {len(data)}")

    timestamp = int.from_bytes(data[0:4], "big") + APPLE_EPOCH_OFFSET
    eph_bytes = data[5:62]
    encrypted = data[62:72]
    tag = data[72:88]

    eph_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP224R1(), eph_bytes)
    shared = private_key.exchange(ec.ECDH(), eph_key)
    derived = hashlib.sha256(shared + b"\x00\x00\x00\x01" + eph_bytes).digest()

    decryptor = Cipher(algorithms.AES(derived[:16]), modes.GCM(derived[16:], tag)).decryptor()
    plain = decryptor.update(encrypted) + decryptor.finalize()

    lat = struct.unpack(">i", plain[0:4])[0] / 1e7
    lon = struct.unpack(">i", plain[4:8])[0] / 1e7
    accuracy = plain[8]
    return timestamp, lat, lon, accuracy


def load_private_key(name):
    keyfile = KEYS_DIR / f"{name}.keys"
    if not keyfile.exists():
        sys.exit(f"{keyfile} not found — run `findmylinux.py keygen` first.")
    fields = dict(
        line.split(": ", 1) for line in keyfile.read_text().strip().splitlines()
    )
    private_key = ec.derive_private_key(
        int.from_bytes(base64.b64decode(fields["Private key"]), "big"), ec.SECP224R1())
    return private_key, fields["Hashed adv key"]


def fetch_fixes(name, days=7, account=None):
    """Return decrypted fixes newest-first as (timestamp, lat, lon, accuracy).

    `days` is accepted for API compatibility but Apple returns whatever recent
    reports it holds; callers that care filter by timestamp. Raises RuntimeError
    on any failure so callers decide whether it is fatal (the daemon retries).
    """
    import apple

    private_key, hashed = load_private_key(name)
    account = account or apple_account()
    if not account.is_logged_in():
        raise RuntimeError("not logged in — run `findmylinux login` "
                           "or sign in from the app.")
    try:
        reports = account.fetch_raw([hashed])
    except apple.LoginError as exc:
        raise RuntimeError(str(exc)) from exc
    except Exception as exc:
        raise RuntimeError(f"could not reach Apple or anisette: {exc}") from exc

    fixes = []
    for report in reports:
        try:
            fixes.append(decrypt_report(report["payload"], private_key))
        except Exception as exc:
            logging.warning("skipped an undecryptable report: %s", exc)
    fixes.sort(reverse=True)
    return fixes


def cmd_login(args):
    import apple
    from getpass import getpass

    account = apple_account()
    if not account.anisette_reachable():
        sys.exit(f"anisette not reachable at {ANISETTE_URL} — is "
                 "findmylinux-anisette.service running?")
    username = args.apple_id or input("Apple ID: ")
    password = getpass("Password: ")

    def code_callback():
        return input("SMS 2FA code (sent to your trusted number): ").strip()

    try:
        account.login(username, password, code_callback)
    except apple.LoginError as exc:
        sys.exit(f"login failed: {exc}")
    print("logged in — token saved. `findmylinux locate` should work now.")


def cmd_locate(args):
    try:
        raw = fetch_fixes(args.name, args.days)
    except RuntimeError as exc:
        sys.exit(str(exc))

    if not raw:
        print(f"no reports in the last {args.days} days — either no Apple device "
              "has passed the laptop yet, or it has not been advertising.")
        return

    window = args.window if args.window is not None else \
        load_config().get("triangulate_window", DEFAULT_WINDOW)
    fixes = triangulate(raw, window)

    note = f", triangulated into {len(fixes)}" if 0 < len(fixes) < len(raw) else ""
    print(f"{len(raw)} reports over {args.days} days{note}\n")
    print(f"{'when':<20} {'latitude':>12} {'longitude':>13}   accuracy")
    for timestamp, lat, lon, accuracy in fixes[:args.limit]:
        when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))
        print(f"{when:<20} {lat:>12.6f} {lon:>13.6f}   {accuracy:>3d} m")

    newest = fixes[0]
    print(f"\nmost recent: https://www.openstreetmap.org/?mlat={newest[1]:.6f}"
          f"&mlon={newest[2]:.6f}#map=17/{newest[1]:.6f}/{newest[2]:.6f}")


def cmd_config(args):
    config = load_config()
    if args.interval is not None:
        config["interval"] = args.interval
    if args.window is not None:
        config["triangulate_window"] = args.window
    if args.interval is not None or args.window is not None:
        save_config(config)
    print(f"update interval     : {config.get('interval', DEFAULT_INTERVAL)} s")
    print(f"triangulate window  : {config.get('triangulate_window', DEFAULT_WINDOW)} s")
    print(f"config file         : {CONFIG_FILE}")


GEOLOCATION_FILE = Path("/etc/geolocation")


def write_geolocation(path, lat, lon, accuracy, timestamp, altitude=0.0):
    when = time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime(timestamp))
    content = (
        f"# written by findmylinux from a Find My report at {when}\n"
        f"{lat:.7f}\n{lon:.7f}\n{altitude:.1f}\n{float(accuracy):.1f}\n"
    ).encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, content)
    finally:
        os.close(fd)


def cmd_location_daemon(args):
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    path = Path(args.file)
    last_written = None

    stopping = False

    def handle_signal(signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    logging.info("feeding geoclue via %s", path)

    while not stopping:
        config = load_config()
        interval = args.interval if args.interval is not None else \
            config.get("interval", DEFAULT_INTERVAL)
        window = args.window if args.window is not None else \
            config.get("triangulate_window", DEFAULT_WINDOW)

        try:
            fixes = triangulate(fetch_fixes(args.name, args.days), window)
        except RuntimeError as exc:
            logging.warning("%s", exc)
            fixes = []

        if fixes:
            timestamp, lat, lon, accuracy = fixes[0]
            age = time.time() - timestamp
            if age > args.max_age:
                logging.warning(
                    "newest fix is %.0f min old (> max-age %.0f min); leaving "
                    "the last location in place",
                    age / 60, args.max_age / 60)
            elif fixes[0] != last_written:
                write_geolocation(path, lat, lon, accuracy, timestamp)
                last_written = fixes[0]
                logging.info(
                    "updated: %.6f, %.6f  ±%dm  (%.0f min old)",
                    lat, lon, accuracy, age / 60)

        slept = 0
        while slept < interval and not stopping:
            time.sleep(min(2, interval - slept))
            slept += 2

    logging.info("stopped")


class HCIError(RuntimeError):
    pass


class HCISocket:
    """Exclusive control of one controller over an HCI user channel.

    Binding requires the device to be down, and succeeds only for one owner at
    a time — while this socket is open the adapter is invisible to bluetoothd.
    Closing it hands the adapter back.
    """

    def __init__(self, index, attempts=10, power_off=None):
        self.sock = socket.socket(
            socket.AF_BLUETOOTH, socket.SOCK_RAW | socket.SOCK_CLOEXEC,
            socket.BTPROTO_HCI)
        for attempt in range(attempts):
            if power_off:
                power_off()
            try:
                self.sock.bind((index, HCI_CHANNEL_USER))
                break
            except OSError as exc:
                if exc.errno not in (errno.EBUSY, errno.EALREADY) or attempt == attempts - 1:
                    self.sock.close()
                    raise HCIError(
                        f"cannot take hci{index} ({exc.strerror}). "
                        "The adapter must be powered off and not held by another process."
                    ) from exc
                time.sleep(0.5)
        self.sock.settimeout(5)

    def command(self, opcode, params=b"", timeout=5):
        self.sock.send(struct.pack("<BHB", HCI_COMMAND_PKT, opcode, len(params)) + params)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data = self.sock.recv(1024)
            except TimeoutError:
                break
            if len(data) < 3 or data[0] != HCI_EVENT_PKT:
                continue
            code, plen = data[1], data[2]
            body = data[3:3 + plen]
            if code == EVT_CMD_COMPLETE and len(body) >= 3:
                if struct.unpack("<H", body[1:3])[0] != opcode:
                    continue
                status = body[3] if len(body) > 3 else 0
                self._check(opcode, status)
                return body[4:]
            if code == EVT_CMD_STATUS and len(body) >= 4:
                if struct.unpack("<H", body[2:4])[0] != opcode:
                    continue
                self._check(opcode, body[0])
                return b""
        raise HCIError(f"no response to HCI command 0x{opcode:04x}")

    @staticmethod
    def _check(opcode, status):
        if status:
            raise HCIError(f"HCI command 0x{opcode:04x} failed with status 0x{status:02x}")

    def close(self):
        self.sock.close()


def supports_extended_advertising(hci):
    features = hci.command(OP_LE_READ_LOCAL_FEATURES)
    byte, bit = LE_FEATURE_EXT_ADVERTISING
    return len(features) > byte and bool(features[byte] & bit)


def _advertise_legacy(hci, addr, payload, interval_ms):
    interval = round(interval_ms / 0.625)
    params = struct.pack(
        "<HHBBB", interval, interval, ADV_NONCONN_IND, OWN_ADDR_RANDOM, 0x00
    ) + bytes(6) + bytes([0x07, 0x00])

    hci.command(OP_LE_SET_ADV_ENABLE, b"\x00")
    hci.command(OP_LE_SET_RANDOM_ADDRESS, bytes(reversed(addr)))
    hci.command(OP_LE_SET_ADV_PARAMETERS, params)
    hci.command(OP_LE_SET_ADV_DATA, bytes([len(payload)]) + payload.ljust(31, b"\x00"))
    hci.command(OP_LE_SET_ADV_ENABLE, b"\x01")


def _advertise_extended(hci, addr, payload, interval_ms, handle=0x00):
    interval = round(interval_ms / 0.625)
    interval3 = interval.to_bytes(3, "little")

    params = (
        bytes([handle])
        + struct.pack("<H", EXT_PROP_LEGACY_NONCONN)
        + interval3 + interval3
        + bytes([0x07])
        + bytes([OWN_ADDR_RANDOM, 0x00]) + bytes(6)
        + bytes([0x00])
        + bytes([0x7F])
        + bytes([0x01])
        + bytes([0x00])
        + bytes([0x01])
        + bytes([0x00])
        + bytes([0x00])
    )

    hci.command(OP_LE_SET_EXT_ADV_ENABLE, bytes([0x00, 0x00]))
    hci.command(OP_LE_SET_EXT_ADV_PARAMETERS, params)
    hci.command(OP_LE_SET_EXT_ADV_SET_RANDOM_ADDR,
                bytes([handle]) + bytes(reversed(addr)))
    hci.command(OP_LE_SET_EXT_ADV_DATA,
                bytes([handle, 0x03, 0x01, len(payload)]) + payload)
    hci.command(OP_LE_SET_EXT_ADV_ENABLE,
                bytes([0x01, 0x01, handle]) + struct.pack("<H", 0) + bytes([0x00]))


def start_advertising(hci, addr, payload, interval_ms, mode="auto"):
    hci.command(OP_RESET)
    if mode == "auto":
        mode = "extended" if supports_extended_advertising(hci) else "legacy"
    if mode == "extended":
        _advertise_extended(hci, addr, payload, interval_ms)
    else:
        _advertise_legacy(hci, addr, payload, interval_ms)
    return mode


def stop_advertising(hci, mode):
    if mode == "extended":
        hci.command(OP_LE_SET_EXT_ADV_ENABLE, bytes([0x00, 0x00]), timeout=2)
    else:
        hci.command(OP_LE_SET_ADV_ENABLE, b"\x00", timeout=2)


def btmgmt(index, *args, check=True):
    cmd = ["btmgmt", "--index", str(index), *args]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    out = (proc.stdout + proc.stderr).strip()
    if check and (proc.returncode != 0 or "ailed" in out):
        raise HCIError(f"{' '.join(cmd)}\n{out}")
    return out


def require_root():
    if os.geteuid() != 0:
        sys.exit("needs root; run via the systemd unit or with run0/pkexec.")


def adapter_index(name):
    return int(name.removeprefix("hci")) if name.startswith("hci") else int(name)


def cmd_start(args):
    adv_key = load_adv_key(args.name)
    addr, payload = advertisement(adv_key)
    idx = adapter_index(args.adapter)
    require_root()

    hci = HCISocket(idx, power_off=lambda: btmgmt(idx, "power", "off", check=False))

    stopping = False

    def handle_signal(signum, _frame):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    mode = None
    try:
        mode = start_advertising(hci, addr, payload, args.interval, args.mode)
        print(f"advertising as {format_addr(addr)} on {args.adapter} "
              f"every {args.interval} ms ({mode} PDUs)", flush=True)
        print(f"payload {payload.hex()}", flush=True)
        while not stopping:
            signal.pause()
    finally:
        try:
            if mode:
                stop_advertising(hci, mode)
        except (HCIError, OSError):
            pass
        hci.close()
        print("stopped advertising; adapter released", flush=True)


def cmd_restore(args):
    """Hand the adapter back to bluetoothd with its stock settings."""
    idx = adapter_index(args.adapter)
    require_root()
    btmgmt(idx, "power", "off", check=False)
    btmgmt(idx, "static-addr", "00:00:00:00:00:00", check=False)
    btmgmt(idx, "bredr", "on", check=False)
    btmgmt(idx, "connectable", "on", check=False)
    btmgmt(idx, "bondable", "on", check=False)
    btmgmt(idx, "clr-adv", check=False)
    btmgmt(idx, "power", "on", check=False)
    print(f"{args.adapter} restored to normal operation")


def cmd_status(args):
    idx = adapter_index(args.adapter)
    addr, payload = advertisement(load_adv_key(args.name))
    print(f"expected address : {format_addr(addr)}")
    print(f"expected payload : {payload.hex()}")
    print()
    info = btmgmt(idx, "info", check=False)
    print(info)
    if "Permission denied" in info or not info:
        return
    print("adapter is held by findmylinux" if f"hci{idx}" not in info
          else "adapter is under bluetoothd (not advertising via findmylinux)")


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--name", default="laptop", help="key set name (default: laptop)")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="generate an accessory keypair")
    p.add_argument("--force", action="store_true", help="overwrite an existing key set")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("start", help="advertise until terminated (holds the adapter)")
    p.add_argument("--adapter", default="hci0")
    p.add_argument("--interval", type=int, default=2000,
                   help="advertising interval in ms (default: 2000)")
    p.add_argument("--mode", choices=("auto", "extended", "legacy"), default="auto",
                   help="which HCI advertising commands to use (default: auto)")
    p.set_defaults(func=cmd_start)

    p = sub.add_parser("restore", help="hand the adapter back to bluetoothd")
    p.add_argument("--adapter", default="hci0")
    p.set_defaults(func=cmd_restore)

    p = sub.add_parser("status", help="show expected and actual adapter state")
    p.add_argument("--adapter", default="hci0")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("locate", help="fetch and decrypt this laptop's location reports")
    p.add_argument("--days", type=int, default=7, help="how far back to look (default: 7)")
    p.add_argument("--limit", type=int, default=20, help="how many fixes to print")
    p.add_argument("--window", type=int, default=None,
                   help="triangulate reports within N seconds (0 disables)")
    p.set_defaults(func=cmd_locate)

    p = sub.add_parser("login", help="sign in to your Apple ID (needed once)")
    p.add_argument("--apple-id", help="Apple ID email (prompted if omitted)")
    p.set_defaults(func=cmd_login)

    p = sub.add_parser("config", help="show or change update interval and triangulation")
    p.add_argument("--interval", type=int, default=None,
                   help="seconds between location-daemon fetches")
    p.add_argument("--window", type=int, default=None,
                   help="triangulate reports within N seconds (0 disables)")
    p.set_defaults(func=cmd_config)

    p = sub.add_parser("location-daemon",
                       help="feed the newest fix to geoclue as the system location")
    p.add_argument("--interval", type=int, default=None,
                   help="seconds between fetches (default: config or 600)")
    p.add_argument("--window", type=int, default=None,
                   help="triangulate reports within N seconds (default: config or 60)")
    p.add_argument("--days", type=int, default=1,
                   help="how far back to consider reports (default: 1)")
    p.add_argument("--max-age", type=int, default=7200,
                   help="ignore fixes older than this many seconds (default: 7200)")
    p.add_argument("--file", default=str(GEOLOCATION_FILE),
                   help="geoclue static-source file (default: /etc/geolocation)")
    p.set_defaults(func=cmd_location_daemon)

    args = parser.parse_args()
    try:
        args.func(args)
    except HCIError as exc:
        sys.exit(f"error: {exc}")


if __name__ == "__main__":
    main()
