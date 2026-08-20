"""Pure-Python Apple ID login and Find My report fetch.

This replaces the macless-haystack endpoint server: it talks GSA (Grand Slam
Authentication) directly, then queries the offline-finding fetch service. The
only piece it cannot do itself is anisette — the Apple device-attestation
headers, which need Apple's proprietary ADI code — so it fetches those two
headers from a local anisette daemon over HTTP.

Ported from biemster/FindMy and dchristl/macless-haystack (pypush_gsa_icloud),
trimmed to the standard library plus `srp` and `cryptography`:
`pbkdf2`/`pycryptodome` are replaced by `hashlib.pbkdf2_hmac`.
"""

import base64
import hashlib
import hmac
import json
import locale
import plistlib
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path

import requests
import _srp_vendor as srp
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

srp.rfc5054_enable()
srp.no_username_in_x()

GSA_URL = "https://gsa.apple.com/grandslam/GsService2"
AUTH_URL = "https://gsa.apple.com/auth"
VERIFY_URL = "https://gsa.apple.com/auth/verify/phone/securitycode"
RESEND_URL = "https://idmsa.apple.com/appleauth/auth/verify/phone"
MOBILEME_URL = "https://setup.icloud.com/setup/iosbuddy/loginDelegates"
FETCH_URL = "https://gateway.icloud.com/acsnservice/fetch"

APPLE_EPOCH_OFFSET = 978307200

_PLIST_HEADER = (
    b"<?xml version='1.0' encoding='UTF-8'?>\n"
    b"<!DOCTYPE plist PUBLIC '-//Apple//DTD PLIST 1.0//EN' "
    b"'http://www.apple.com/DTDs/PropertyList-1.0.dtd'>\n"
)


class LoginError(RuntimeError):
    pass


class AppleAccount:
    """An Apple ID session that can fetch Find My reports.

    The device identity (user_id/device_id) is persisted: Apple binds the
    search-party token to the device that logged in and rejects any other, so a
    fresh identity per process would invalidate the token on every restart.
    """

    def __init__(self, anisette_url, data_dir):
        self.anisette_url = anisette_url.rstrip("/")
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.identity_file = self.data_dir / "device_identity.json"
        self.token_file = self.data_dir / "auth.json"
        self.user_id, self.device_id = self._load_identity()
        self.ca_bundle = self._build_ca_bundle()

    def _build_ca_bundle(self):
        """A CA bundle trusting the public roots plus Apple's own root.

        gsa.apple.com chains to 'Apple Root CA', which Apple publishes but which
        is absent from the public trust store — so a default verify fails. The
        other endpoints (setup/gateway.icloud.com) use public CAs. Trusting both
        keeps full verification instead of the verify=False every other tool in
        this space resorts to.
        """
        import requests.certs

        apple_ca = (Path(__file__).resolve().parent / "apple_root_ca.pem").read_text()
        bundle = self.data_dir / "ca-bundle.pem"
        combined = Path(requests.certs.where()).read_text() + "\n" + apple_ca
        if not bundle.exists() or bundle.read_text() != combined:
            bundle.write_text(combined)
        return str(bundle)


    def _load_identity(self):
        if self.identity_file.exists():
            saved = json.loads(self.identity_file.read_text())
            return saved["user_id"], saved["device_id"]
        identity = {"user_id": str(uuid.uuid4()).upper(),
                    "device_id": str(uuid.uuid4()).upper()}
        self.identity_file.write_text(json.dumps(identity, indent=2) + "\n")
        self.identity_file.chmod(0o600)
        return identity["user_id"], identity["device_id"]

    def is_logged_in(self):
        return self.token_file.exists()

    def logout(self):
        self.token_file.unlink(missing_ok=True)

    def _save_token(self, dsid, search_party_token):
        self.token_file.write_text(json.dumps(
            {"dsid": dsid, "searchPartyToken": search_party_token}))
        self.token_file.chmod(0o600)

    def _load_token(self):
        token = json.loads(self.token_file.read_text())
        return token["dsid"], token["searchPartyToken"]


    def anisette_reachable(self):
        try:
            requests.get(self.anisette_url, timeout=5).raise_for_status()
            return True
        except requests.RequestException:
            return False

    def _anisette_headers(self):
        response = requests.get(self.anisette_url, timeout=10)
        response.raise_for_status()
        data = response.json()
        headers = {
            "X-Apple-I-MD": data["X-Apple-I-MD"],
            "X-Apple-I-MD-M": data["X-Apple-I-MD-M"],
        }
        headers.update(self._meta_headers())
        return headers

    def _meta_headers(self):
        loc = locale.getlocale()[0] or "en_US"
        return {
            "X-Apple-I-Client-Time":
                datetime.now(timezone.utc).replace(microsecond=0).isoformat() + "Z",
            "X-Apple-I-TimeZone": str(datetime.now(timezone.utc).astimezone().tzinfo),
            "loc": loc,
            "X-Apple-Locale": loc,
            "X-Apple-I-MD-RINFO": "17106176",
            "X-Apple-I-MD-LU": base64.b64encode(self.user_id.encode()).decode(),
            "X-Mme-Device-Id": self.device_id,
            "X-Apple-I-SRL-NO": "0",
        }


    def login(self, username, password, code_callback):
        """Obtain and persist a token. code_callback() -> str is called (after
        an SMS is sent) whenever a 2FA code is needed."""
        spd = self._gsa_authenticate(username, password, code_callback)
        pet = spd["t"]["com.apple.gs.idms.pet"]["token"]
        adsid = spd["adsid"]

        body = plistlib.dumps({
            "apple-id": username,
            "delegates": {"com.apple.mobileme": {}},
            "password": pet,
            "client-id": self.user_id,
        })
        headers = {
            "X-Apple-ADSID": adsid,
            "User-Agent": "com.apple.iCloudHelper/282 CFNetwork/1408.0.4 Darwin/22.5.0",
            "X-Mme-Client-Info":
                "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> "
                "<com.apple.AOSKit/282 (com.apple.accountsd/113)>",
        }
        headers.update(self._anisette_headers())

        resp = requests.post(MOBILEME_URL, auth=(username, pet), data=body,
                             headers=headers, timeout=10, verify=self.ca_bundle)
        resp.raise_for_status()
        result = plistlib.loads(resp.content)
        delegate = result["delegates"]["com.apple.mobileme"]
        if delegate.get("status") != 0:
            message = delegate.get("status-message", "unknown error")
            if "score" in message.lower() or "blocking" in message.lower():
                message += ("\n\nApple flags accounts with little history. Add a "
                            "payment method at appleid.apple.com and try again.")
            raise LoginError(message)
        tokens = delegate["service-data"]["tokens"]
        self._save_token(result["dsid"], tokens["searchPartyToken"])

    def _gsa_authenticate(self, username, password, code_callback):
        user = srp.User(username, b"", hash_alg=srp.SHA256, ng_type=srp.NG_2048)
        _, a = user.start_authentication()
        r = self._gsa_request({"A2k": a, "ps": ["s2k", "s2k_fo"],
                               "u": username, "o": "init"})
        if r["Status"].get("ec"):
            raise LoginError(r["Status"].get("em", "authentication rejected"))
        if r["sp"] not in ("s2k", "s2k_fo"):
            raise LoginError(f"unsupported protocol {r['sp']}")

        user.p = _derive_password(password, r["s"], r["i"], r["sp"])
        m = user.process_challenge(r["s"], r["B"])
        if m is None:
            raise LoginError("failed to process SRP challenge")

        resp = self._gsa_request({"c": r["c"], "M1": m, "u": username,
                                  "o": "complete"})
        status = resp["Status"]
        if status.get("ec"):
            raise LoginError(status.get("em", "wrong Apple ID or password"))
        if "M2" not in resp:
            raise LoginError("authentication failed (no server proof)")
        user.verify_session(resp["M2"])
        if not user.authenticated():
            raise LoginError("could not verify Apple's session (possible imposter)")

        spd = plistlib.loads(_PLIST_HEADER + _decrypt_spd(user, resp["spd"]))
        if status.get("au") in ("trustedDeviceSecondaryAuth", "secondaryAuth"):
            self._sms_2fa(spd, code_callback)
            return self._gsa_authenticate(username, password, code_callback)
        if "au" in status:
            raise LoginError(f"unsupported 2FA method: {status['au']}")
        return spd

    def _gsa_request(self, parameters):
        cpd = {"bootstrap": True, "icscrec": True, "pbe": False,
               "prkgen": True, "svct": "iCloud"}
        cpd.update(self._anisette_headers())
        body = {"Header": {"Version": "1.0.1"},
                "Request": {"cpd": cpd, **parameters}}
        headers = {
            "Content-Type": "text/x-xml-plist",
            "Accept": "*/*",
            "User-Agent": "akd/1.0 CFNetwork/978.0.7 Darwin/18.7.0",
            "X-MMe-Client-Info":
                "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> "
                "<com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>",
        }
        resp = requests.post(GSA_URL, headers=headers,
                            data=plistlib.dumps(body), timeout=10,
                            verify=self.ca_bundle)
        resp.raise_for_status()
        return plistlib.loads(resp.content)["Response"]

    def _sms_2fa(self, spd, code_callback):
        for key, value in list(spd.items()):
            if isinstance(value, bytes):
                spd[key] = base64.b64encode(value).decode()
        identity_token = base64.b64encode(
            (spd["adsid"] + ":" + spd["GsIdmsToken"]).encode()).decode()
        headers = {
            "User-Agent": "Xcode",
            "Accept-Language": "en-us",
            "X-Apple-Identity-Token": identity_token,
            "X-Apple-App-Info": "com.apple.gs.xcode.auth",
            "X-Xcode-Version": "11.2 (11B41)",
            "X-Mme-Client-Info":
                "<MacBookPro18,3> <Mac OS X;13.4.1;22F8> "
                "<com.apple.AOSKit/282 (com.apple.dt.Xcode/3594.4.19)>",
        }
        headers.update(self._anisette_headers())

        sms_id = 1
        auth = requests.get(AUTH_URL, headers=headers, timeout=10,
                            verify=self.ca_bundle)
        match = re.search(r'<script.*class="boot_args">\s*(.*?)\s*</script>',
                          auth.text, re.DOTALL)
        if match:
            try:
                boot_args = json.loads(match.group(1).strip())
                sms_id = boot_args["direct"]["phoneNumberVerification"][
                    "trustedPhoneNumber"]["id"]
            except (KeyError, json.JSONDecodeError):
                pass

        requests.put(RESEND_URL,
                     json={"phoneNumber": {"id": sms_id}, "mode": "sms"},
                     headers=headers, timeout=10, verify=self.ca_bundle)
        code = code_callback()
        if not code:
            raise LoginError("no 2FA code entered")

        resp = requests.post(VERIFY_URL, headers=headers, timeout=10,
                             verify=self.ca_bundle, json={
            "phoneNumber": {"id": sms_id}, "mode": "sms",
            "securityCode": {"code": str(code).strip()}})
        if not (resp.ok and "X-Apple-DSID" in resp.headers):
            raise LoginError("2FA failed — wrong code or number")


    def fetch_raw(self, hashed_ids):
        """Return Apple's raw report list for the given hashed advertisement
        keys. Raises LoginError(401) if the token is invalid."""
        dsid, token = self._load_token()
        resp = requests.post(
            FETCH_URL, auth=(dsid, token), headers=self._anisette_headers(),
            json={"search": [{"startDate": 1, "ids": list(hashed_ids)}]},
            timeout=60, verify=self.ca_bundle)
        if resp.status_code == 401:
            raise LoginError("Apple rejected the token (401) — log in again")
        resp.raise_for_status()
        return resp.json().get("results", [])


def _derive_password(password, salt, iterations, protocol):
    digest = hashlib.sha256(password.encode()).digest()
    if protocol == "s2k_fo":
        digest = digest.hex().encode()
    return hashlib.pbkdf2_hmac("sha256", digest, salt, iterations, dklen=32)


def _session_key(user, name):
    return hmac.new(user.get_session_key(), name.encode(), hashlib.sha256).digest()


def _decrypt_spd(user, data):
    key = _session_key(user, "extra data key:")
    iv = _session_key(user, "extra data iv:")[:16]
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    plain = decryptor.update(data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(plain) + unpadder.finalize()
