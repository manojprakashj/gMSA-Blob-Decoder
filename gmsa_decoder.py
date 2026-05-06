#!/usr/bin/env python3
"""
gMSA Blob Decoder & Kerberos Key Derivation Tool
=================================================
Decodes Group Managed Service Account (gMSA) password blobs and
derives Kerberos encryption keys (AES128, AES256, RC4/NTLM).

Author  : Manoj Prakash J
Usage   : python3 gmsa_decoder.py [options]
"""

import argparse
import base64
import hashlib
import hmac
import json
import logging
import struct
import sys
from binascii import unhexlify
from datetime import datetime, timezone
from pathlib import Path

try:
    from impacket.krb5.crypto import _AES256CTS, _AES128CTS, string_to_key
    from impacket.krb5 import constants
    IMPACKET_AVAILABLE = True
except ImportError:
    IMPACKET_AVAILABLE = False

try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    CLIPBOARD_AVAILABLE = False


class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

    @staticmethod
    def disable():
        for attr in ("RED","GREEN","YELLOW","CYAN","BOLD","DIM","RESET"):
            setattr(C, attr, "")


def banner():
    art = r"""
          __  ________ ___       ____  __      __       ____                      __
   ____ _/  |/  / ___//   |     / __ )/ /___  / /_     / __ \___  _________  ____/ /__  _____
  / __ `/ /|_/ /\__ \/ /| |    / __  / / __ \/ __ \   / / / / _ \/ ___/ __ \/ __  / _ \/ ___/
 / /_/ / /  / /___/ / ___ |   / /_/ / / /_/ / /_/ /  / /_/ /  __/ /__/ /_/ / /_/ /  __/ /
 \__, /_/  /_//____/_/  |_|  /_____/_/\____/_.___/  /_____/\___/\___/\____/\__,_/\___/_/
/____/

By ManojPrakash
"""
    print(f"{C.CYAN}{C.BOLD}{art}{C.RESET}")



ETYPE_AES256 = 18
ETYPE_AES128 = 17
ETYPE_RC4    = 23   # RC4-HMAC / NTLM

def decode_gmsa_blob(b64_or_hex: str, source_format: str = "auto") -> bytes:
    """Decode a gMSA blob from base64 or hex, return raw bytes."""
    data = b64_or_hex.strip()

    if source_format == "auto":
        try:
            raw = base64.b64decode(data)
            logging.debug("Detected base64 encoding")
            return raw
        except Exception:
            pass
        try:
            raw = unhexlify(data.replace(" ", "").replace(":", ""))
            logging.debug("Detected hex encoding")
            return raw
        except Exception:
            pass
        raise ValueError("Could not decode blob — provide valid base64 or hex")

    if source_format == "base64":
        return base64.b64decode(data)
    if source_format in ("hex", "hexdump"):
        return unhexlify(data.replace(" ", "").replace(":", ""))
    raise ValueError(f"Unknown format: {source_format}")


def extract_password_from_blob(raw: bytes, verbose: bool = False) -> tuple[bytes, str]:
    """
    Parse gMSA MSDS-ManagedPassword blob (MS-ADTS 2.2.27).

    Structure:
      Version    : 2 bytes  (0x0001)
      Reserved   : 2 bytes
      Length     : 4 bytes  (total blob length)
      CurrentPwd : 4 bytes  offset
      PreviousPwd: 4 bytes  offset (may be 0)
      QueryInterval: 4 bytes
      UnchangedInterval: 4 bytes
      Password data follows at offsets…
    """
    if len(raw) < 24:
        # Fallback: assume raw blob is password bytes starting at offset 0
        logging.warning("Blob shorter than expected MSDS header — treating as raw password bytes")
        pwd_bytes = raw[:256]
        return pwd_bytes, "raw"

    version = struct.unpack_from("<H", raw, 0)[0]
    if version == 1:
        # Properly structured blob
        cur_pwd_offset = struct.unpack_from("<H", raw, 4)[0]
        cur_pwd_len    = struct.unpack_from("<H", raw, 6)[0]
        if verbose:
            print(f"  {C.DIM}Blob version     : {version}{C.RESET}")
            print(f"  {C.DIM}Pwd offset       : 0x{cur_pwd_offset:04x}{C.RESET}")
            print(f"  {C.DIM}Pwd length       : {cur_pwd_len} bytes{C.RESET}")
        pwd_bytes = raw[cur_pwd_offset: cur_pwd_offset + cur_pwd_len]
        return pwd_bytes, "structured"

    # Unstructured / LDAP raw blob — password is first 256 bytes (UTF-16LE)
    pwd_bytes = raw[:256]
    return pwd_bytes, "raw"


def derive_keys(pwd_bytes: bytes, salt: str, etype_list: list[int] | None = None) -> dict:
    """Derive Kerberos keys from gMSA password bytes + salt."""
    if not IMPACKET_AVAILABLE:
        raise RuntimeError("impacket is required: pip install impacket")

    results = {}
    salt_b = salt.encode("utf-8")

    # Encode password: interpret bytes as UTF-16LE string → encode UTF-8 for KDF
    try:
        pwd_str = pwd_bytes.decode("utf-16-le", errors="replace")
        pwd_utf8 = pwd_str.encode("utf-8")
    except Exception as e:
        raise ValueError(f"Failed to decode password bytes: {e}") from e

    etypes = etype_list or [ETYPE_AES256, ETYPE_AES128, ETYPE_RC4]

    for etype in etypes:
        try:
            if etype == ETYPE_AES256:
                key = _AES256CTS.string_to_key(pwd_utf8, salt_b, b'\x00\x00\x10\x00')
                results["aes256"] = key.contents.hex()

            elif etype == ETYPE_AES128:
                key = _AES128CTS.string_to_key(pwd_utf8, salt_b, b'\x00\x00\x10\x00')
                results["aes128"] = key.contents.hex()

            elif etype == ETYPE_RC4:
                # RC4/NTLM: MD4 of UTF-16LE password
                import hashlib
                nt_hash = hashlib.new("md4", pwd_bytes).hexdigest()
                results["rc4_ntlm"] = nt_hash

        except Exception as e:
            results[f"etype_{etype}_error"] = str(e)
            logging.error("Key derivation failed for etype %d: %s", etype, e)

    return results


def validate_salt(salt: str) -> bool:
    """Basic salt format check (should contain realm + principal)."""
    return len(salt) > 4 and "@" not in salt  # typical: REALM.LOCALhostname$


def print_results(keys: dict, salt: str, blob_type: str, args):
    print(f"\n{C.BOLD}{'─'*54}{C.RESET}")
    print(f"  {C.BOLD}Results{C.RESET}")
    print(f"{'─'*54}")
    print(f"  Salt          : {C.YELLOW}{salt}{C.RESET}")
    print(f"  Blob type     : {C.DIM}{blob_type}{C.RESET}")
    print(f"  Timestamp     : {C.DIM}{datetime.now(timezone.utc).isoformat()}Z{C.RESET}")
    print(f"{'─'*54}")

    key_labels = {
        "aes256"   : ("AES-256 Key  ", C.GREEN),
        "aes128"   : ("AES-128 Key  ", C.CYAN),
        "rc4_ntlm" : ("RC4/NTLM Hash", C.YELLOW),
    }

    for k, v in keys.items():
        if k.endswith("_error"):
            print(f"  {C.RED}⚠  {k}: {v}{C.RESET}")
        else:
            label, colour = key_labels.get(k, (k, C.RESET))
            print(f"  {C.BOLD}{label}{C.RESET} : {colour}{v}{C.RESET}")

    print(f"{'─'*54}\n")

    if CLIPBOARD_AVAILABLE and args.copy:
        copy_val = keys.get("aes256") or next(iter(keys.values()), "")
        pyperclip.copy(copy_val)
        print(f"  {C.DIM}[✓] AES-256 key copied to clipboard{C.RESET}\n")


def save_output(keys: dict, salt: str, blob_type: str, out_path: Path):
    data = {
        "timestamp" : datetime.now(timezone.utc).isoformat() + "Z",
        "salt"      : salt,
        "blob_type" : blob_type,
        "keys"      : keys,
    }
    out_path.write_text(json.dumps(data, indent=2))
    print(f"  {C.GREEN}[✓] Results saved → {out_path}{C.RESET}\n")



def interactive_mode(args):
    print(f"{C.CYAN}[Interactive Mode]{C.RESET}\n")

    blob_input = input(f"  {C.BOLD}Blob (base64 or hex){C.RESET}: ").strip()
    if not blob_input:
        print(f"{C.RED}[!] No blob provided.{C.RESET}")
        sys.exit(1)

    salt = input(f"  {C.BOLD}Salt{C.RESET} (e.g. DOMAIN.LOCALhostname$): ").strip()
    if not salt:
        print(f"{C.RED}[!] Salt is required.{C.RESET}")
        sys.exit(1)

    derive_aes128 = input(f"  Derive AES-128 key? [y/N]: ").strip().lower() == "y"
    derive_rc4    = input(f"  Derive RC4/NTLM hash? [y/N]: ").strip().lower() == "y"

    etypes = [ETYPE_AES256]
    if derive_aes128: etypes.append(ETYPE_AES128)
    if derive_rc4:    etypes.append(ETYPE_RC4)

    run(blob_input, salt, etypes, args)


def run(blob_input: str, salt: str, etypes: list[int], args):
    try:
        raw = decode_gmsa_blob(blob_input, source_format=args.format)
    except ValueError as e:
        print(f"{C.RED}[!] Blob decode error: {e}{C.RESET}")
        sys.exit(1)

    if args.verbose:
        print(f"\n  {C.DIM}Raw blob size : {len(raw)} bytes{C.RESET}")
        print(f"  {C.DIM}Hex preview   : {raw[:16].hex()}…{C.RESET}")

    try:
        pwd_bytes, blob_type = extract_password_from_blob(raw, verbose=args.verbose)
    except Exception as e:
        print(f"{C.RED}[!] Blob parse error: {e}{C.RESET}")
        sys.exit(1)

    if not validate_salt(salt):
        print(f"{C.YELLOW}[!] Salt looks unusual — expected format: REALM.LOCALprincipal${C.RESET}")

    try:
        keys = derive_keys(pwd_bytes, salt, etypes)
    except RuntimeError as e:
        print(f"{C.RED}[!] {e}{C.RESET}")
        sys.exit(1)
    except ValueError as e:
        print(f"{C.RED}[!] Key derivation error: {e}{C.RESET}")
        sys.exit(1)

    print_results(keys, salt, blob_type, args)

    if args.output:
        save_output(keys, salt, blob_type, Path(args.output))



def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="gmsa_decoder",
        description="Decode gMSA password blobs and derive Kerberos keys",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Interactive mode (no arguments)
  python3 gmsa_decoder.py

  # Pipe from file, AES256 only
  python3 gmsa_decoder.py -b $(cat blob.b64) -s CORP.LOCALsvc_app$

  # All key types, save JSON output
  python3 gmsa_decoder.py -b <blob> -s <salt> --all-keys -o results.json

  # Hex blob input
  python3 gmsa_decoder.py -b deadbeef... --format hex -s CORP.LOCALsvc$
"""
    )
    p.add_argument("-b", "--blob",    help="gMSA password blob (base64 or hex)")
    p.add_argument("-s", "--salt",    help="Kerberos salt (e.g. DOMAIN.LOCALhostname$)")
    p.add_argument("-f", "--format",  choices=["auto","base64","hex"], default="auto",
                   help="Blob encoding format (default: auto-detect)")
    p.add_argument("--aes256",        action="store_true", default=True,
                   help="Derive AES-256 key (default: on)")
    p.add_argument("--aes128",        action="store_true", help="Derive AES-128 key")
    p.add_argument("--rc4",           action="store_true", help="Derive RC4/NTLM hash")
    p.add_argument("--all-keys",      action="store_true", help="Derive all key types")
    p.add_argument("-o", "--output",  metavar="FILE",
                   help="Save results as JSON to FILE")
    p.add_argument("-c", "--copy",    action="store_true",
                   help="Copy AES-256 key to clipboard (requires pyperclip)")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    p.add_argument("--no-color",      action="store_true", help="Disable ANSI colours")
    p.add_argument("--no-banner",     action="store_true", help="Suppress banner")
    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    if args.no_color:
        C.disable()

    if not args.no_banner:
        banner()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s"
    )

    if not IMPACKET_AVAILABLE:
        print(f"{C.RED}[!] impacket not found. Install with: pip install impacket{C.RESET}")
        sys.exit(1)

    etypes = []
    if args.all_keys:
        etypes = [ETYPE_AES256, ETYPE_AES128, ETYPE_RC4]
    else:
        if args.aes256: etypes.append(ETYPE_AES256)
        if args.aes128: etypes.append(ETYPE_AES128)
        if args.rc4:    etypes.append(ETYPE_RC4)
    if not etypes:
        etypes = [ETYPE_AES256]

    # No blob/salt → interactive
    if not args.blob or not args.salt:
        interactive_mode(args)
    else:
        run(args.blob, args.salt, etypes, args)


if __name__ == "__main__":
    main()
