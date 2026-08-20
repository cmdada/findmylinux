# findmylinux

Makes this laptop advertise itself on Apple's [Find My
network](https://developer.apple.com/find-my/) as an
[OpenHaystack](https://github.com/seemoo-lab/openhaystack) accessory. Any
passing iPhone picks up the advertisement and uploads an encrypted location
report to Apple; only the private key in `keys/` can decrypt those reports.

This is the tag half only — it broadcasts. Fetching and displaying the reports
needs a separate piece (see [Seeing the locations](#seeing-the-locations)).

## Install

From the AUR (builds the native anisette daemon as a separate package):

```sh
paru -S findmylinux          # pulls findmylinux-anisette as a dependency
systemctl --user enable --now findmylinux-anisette
findmylinux keygen
findmylinux login            # Apple ID + SMS, or use the app's Sign in
sudo systemctl enable --now findmylinux           # start advertising
systemctl --user enable --now findmylinux-location
```

Or from a checkout, for development:

```sh
./findmylinux.py keygen
pkexec ./install.sh
systemctl start findmylinux
```

The PKGBUILDs live under `packaging/aur/`. `findmylinux` is `arch=any` (pure
Python); `findmylinux-anisette` builds `anisette-v3-server` with `ldc`/`dub`, so
a Python version bump never breaks the app.

## Usage

```sh
findmylinux keygen              # generate a keypair (once)
systemctl start findmylinux     # begin advertising
systemctl stop findmylinux      # stop; the adapter is handed back automatically
findmylinux status              # expected vs. actual adapter state
findmylinux restore             # force the adapter back to bluetoothd
```

`start` runs in the foreground and holds the adapter until terminated, so it is
normally driven through systemd rather than by hand. It takes `--adapter hci1`
if you move this to a dedicated USB Bluetooth dongle, `--interval` for the
advertising interval, and `--mode legacy|extended` to override the automatic
choice of HCI commands.

## Why this doesn't use BlueZ's normal API

The accessory public key is 28 bytes and does not fit in an advertisement, so
the first six bytes travel in the BLE advertising *address* and the remaining
22 fill a manufacturer-specific element that occupies all 31 bytes of a legacy
advertisement. BlueZ's management API cannot express that packet, in either of
its two forms:

- `Add Advertising` reserves three bytes to insert its own Flags element, so it
  rejects a 31-byte payload with `Invalid Parameters` (0x0d). Supplying a Flags
  element yourself is accepted, but then only 28 bytes remain — not enough for
  the key.
- `Add Extended Advertising` accepts the full payload, but assigns its own
  non-resolvable address (so reports would decrypt to nothing) and emits
  extended PDUs on a secondary channel, which Find My scanners ignore.

So the controller is driven directly over an **HCI user channel**, the same
packet the OpenHaystack ESP32 firmware sends. Upstream's own Linux script
(`Firmware/Linux_HCI/HCI.py`) does not work here either: it shells out to
`hcitool`, which Arch dropped from `bluez-utils`, and sets the adapter address
with HCI vendor command `0x3f 0x001` — a Broadcom command, on a MediaTek
controller.

On this laptop's MediaTek controller the legacy `LE Set Advertising Enable`
command is refused with `Invalid HCI Command Parameters` (0x12) even though
every parameter is accepted. The working path is the *extended* advertising
commands with the legacy PDU property bit (`0x0010`), which produces an
ordinary `ADV_NONCONN_IND` on air while allowing a per-set random address.
`--mode` exists because that is a controller quirk, not a universal truth.

## Bluetooth stops working entirely while this runs

An HCI user channel is exclusive: the adapter disappears from bluetoothd, so
neither classic nor LE Bluetooth is available. Your Ear (3) and the Xbox
controller will not connect until the service stops, at which point the adapter
is handed straight back — pairings survive.

To have both at once, put a cheap USB Bluetooth dongle (CSR8510, RTL8761B) on
`hci1` and point the service at it with `--adapter hci1`. A USB *WiFi* adapter
does not help; it has no Bluetooth radio.

## Other things worth knowing

- **It only broadcasts while the laptop is awake.** Suspend or shutdown ends
  advertising, so this will not locate a stolen laptop sitting closed in a bag.
  Keeping it useful there means stopping the lid from suspending, which this
  does not touch.
- **The key is static.** Real AirTags rotate their key every 15 minutes;
  OpenHaystack accessories do not. Anyone within Bluetooth range who logs
  advertisements can recognise this laptop across places and days, and iOS and
  Android unwanted-tracker detection may flag it as an unknown accessory
  following you.
- **`keys/` is the whole secret.** `laptop.keys` holds the private key that
  decrypts every location report ever filed for this machine. The directory is
  `0700` and gitignored. Losing it means the reports are unreadable; leaking it
  means someone else can read your location history.
- Reports take roughly 15–30 minutes to appear after an iPhone sees the
  advertisement, and only exist if an Apple device actually passed nearby.

## Report side: signing in and fetching

Being located is only half of it — the reports sit encrypted on Apple's servers
under your key. findmylinux talks to Apple **directly** (no separate endpoint
server); the only external piece is a local **anisette** daemon that produces
the two device-attestation headers Apple's login and fetch require, which can't
be computed in pure Python.

- **anisette** (`findmylinux-anisette.service`) is `anisette-v3-server` built
  natively from source — the same code the old Docker image ran, minus the
  container. Bound to `127.0.0.1:6969`. On first start it downloads Apple's ADI
  library to `~/.local/share/findmylinux/anisette`.
- **Sign in** once, in the app (menu → *Sign in to Apple ID*) or on the CLI:

  ```sh
  findmylinux login
  ```

  It asks for your Apple ID, password, and an SMS code. The password goes only
  to Apple; only the resulting token is stored (`keys/apple/auth.json`, 0600).

- `findmylinux locate` prints the recent history; `findmylinux-location.service`
  writes the newest fix to `/etc/geolocation` for geoclue.

The Apple auth + fetch is a pure-Python port (`apple.py`) of macless-haystack's
`pypush_gsa_icloud` and biemster/FindMy, trimmed to the standard library plus
`srp` and `cryptography`. It keeps a **persistent device identity** in
`keys/apple/device_identity.json`: Apple binds the token to the device that
logged in, so a fresh identity per run would 401 the token — and the token is
bound to the anisette machine too, so re-provisioning anisette means signing in
again.

## System location (geoclue)

`findmylinux-location.service` feeds the Find My fix to **geoclue**, the Linux
system location service, so anything that asks the system where it is — Firefox,
GNOME/KDE, automatic timezone — gets the laptop's Find My position.

It works through geoclue's *static source*, which reads `/etc/geolocation`
(four lines: latitude, longitude, altitude, accuracy-radius) and monitors it for
changes. The file is owned by your user so the daemon can update it without
privileges; geoclue reads it as root. `[static-source]` is enabled by default in
`/etc/geoclue/geoclue.conf`.

Check what the system reports:

```sh
/usr/lib/geoclue-2.0/demos/where-am-i
```

geoclue merges sources and reports the most accurate one, so a ~80 m Find My fix
takes precedence over the IP-based fallback (kilometre-scale). If no report is
newer than `--max-age` (default 2 h), the daemon leaves the last fix in place
rather than asserting a stale position as current.

## Tests

```sh
python3 test_encoding.py
```

Checks the advertisement encoding against a vector generated by upstream's own
`HCI.py`, and that all 28 key bytes survive the split between the address and
the payload. A wrong byte there fails silently — the laptop still advertises,
iPhones still file reports, and every one of them decrypts to garbage.

To see what actually goes on air, run `btmon` as root while the service starts.
The `LE Set Extended Advertising Parameters` block should read `Use legacy
advertising PDUs: ADV_NONCONN_IND`, and the address should match the one
`findmylinux status` prints.

## Files

| path | purpose |
|---|---|
| `findmylinux.py` | keygen, advertisement construction, HCI user channel |
| `systemd/findmylinux.service` | the advertiser, enabled at boot |
| `systemd/findmylinux-resume.service` | re-arms it after suspend |
| `findmylinux-gui.py` | libadwaita desktop app (map, status, history) |
| `test_encoding.py` | pins the Apple advertisement wire format |
| `apple.py` | pure-Python Apple ID login + Find My fetch |
| `apple_root_ca.pem` | Apple's root, pinned so TLS to gsa.apple.com verifies |
| `packaging/aur/` | PKGBUILDs for `findmylinux` and `findmylinux-anisette` |
| `systemd/` | dev systemd units (packaged versions are in `packaging/`) |
| `~/.local/share/findmylinux/` | keys, Apple token, anisette state (per-user) |
