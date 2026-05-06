# gMSA Blob Decoder & Kerberos Key Derivation Tool

A command-line tool for security researchers and Active Directory administrators to decode **Group Managed Service Account (gMSA)** password blobs and derive Kerberos encryption keys.

> **Intended for authorised security testing, red team engagements, and AD administration only.**

---

## Features

| Feature | Description |
|---|---|
| **Multi-format input** | Auto-detects base64 or hex blob encoding |
| **AES-256 derivation** | Full Kerberos AES-256-CTS-HMAC-SHA1 key |
| **AES-128 derivation** | AES-128-CTS-HMAC-SHA1 key |
| **RC4 / NTLM hash** | MD4-based NT hash from password bytes |
| **Structured blob parsing** | Parses MS-ADTS `MSDS-ManagedPassword` blob format |
| **JSON output** | Save results to file for reporting |
| **Clipboard copy** | Instantly copy AES-256 key (`-c` flag) |
| **Interactive mode** | Guided prompts when no args are passed |
| **Verbose / debug** | Hex previews, blob offsets, derivation trace |
| **Color output** | ANSI-coloured terminal output (disable with `--no-color`) |

---

## Prerequisites

```bash
pip install impacket
pip install pyperclip   # optional — clipboard support
```

Python 3.10+ required.

---

## Installation

```bash
git clone https://github.com/yourname/gmsa-decoder.git
cd gmsa-decoder
pip install -r requirements.txt
```

**requirements.txt**
```
impacket>=0.12.0
pyperclip>=1.9.0   # optional
```

---

## Usage

### Interactive mode (no arguments)

```bash
python3 gmsa_decoder.py
```

You will be prompted for the blob, salt, and which key types to derive. (Used this tool in the HackTheBox - Season 10 PingPong Machine.)

<img width="1557" height="658" alt="image" src="https://github.com/user-attachments/assets/947051eb-30d5-4b66-97d9-5cde09636c66" />

---

### CLI mode

```bash
python3 gmsa_decoder.py -b <blob> -s <salt> [options]
```

#### Options

```
  -b, --blob TEXT        gMSA password blob (base64 or hex)
  -s, --salt TEXT        Kerberos salt  e.g.  CORP.LOCALsvc_app$
  -f, --format           auto | base64 | hex  (default: auto)
      --aes256           Derive AES-256 key (on by default)
      --aes128           Also derive AES-128 key
      --rc4              Also derive RC4/NTLM hash
      --all-keys         Derive all key types at once
  -o, --output FILE      Save JSON results to FILE
  -c, --copy             Copy AES-256 key to clipboard
  -v, --verbose          Show blob structure, offsets, debug info
      --no-color         Disable ANSI colour output
      --no-banner        Suppress ASCII banner
```

---

## Examples

### Basic AES-256 only

```bash
python3 gmsa_decoder.py \
  -b "AQAAANCMnd8BFdERjHoAwE/Cl..." \
  -s "CORP.LOCALsvc_backup$"
```

### All key types + save to JSON

```bash
python3 gmsa_decoder.py \
  -b "AQAAANCMnd8BFdERjHoAwE/Cl..." \
  -s "CORP.LOCALsvc_backup$" \
  --all-keys \
  -o results.json
```

### Hex blob input, verbose

```bash
python3 gmsa_decoder.py \
  -b "0100000000100000..." \
  --format hex \
  -s "CORP.LOCALsvc_backup$" \
  -v
```

### Pipe blob from file

```bash
python3 gmsa_decoder.py \
  -b "$(cat blob.b64)" \
  -s "CORP.LOCALsvc_app$" \
  --all-keys -c
```

## Background : What is a gMSA blob?

Group Managed Service Accounts store passwords as `MSDS-ManagedPassword` blobs in Active Directory. These blobs follow the structure defined in **MS-ADTS § 2.2.27**:

```
Offset  Size  Field
──────────────────────────────
0x00    2     Version (0x0001)
0x02    2     Reserved
0x04    2     CurrentPassword offset
0x06    2     CurrentPassword length
0x08    2     PreviousPassword offset (0 if none)
…             Password data (UTF-16LE)
```

The raw password bytes are fed into the Kerberos `string_to_key` function along with a salt (`REALM` + principal name) to produce AES session keys, or hashed with MD4 to produce the NT hash.

This tool automates that derivation and useful when:
- Auditing gMSA delegation misconfigurations
- Validating Kerberos key derivation in lab environments
- Post-exploitation analysis during authorised red team ops

---

## How the Salt is Constructed

The Kerberos salt for a gMSA is typically:

```
<REALM (uppercase)><sAMAccountName without $>
```

Example: account `svc_app$` in domain `corp.local` →  
salt = `CORP.LOCALsvc_app`

Some environments append `$` try both if derivation fails.

---


## Disclaimer

This tool is provided for **educational and authorised security research purposes only**.  
Unauthorised access to computer systems is illegal. The authors accept no liability for misuse.  
Always obtain written permission from the asset owner before conducting security testing.

---

## References

- [MS-ADTS 2.2.27  MSDS-ManagedPassword](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-cce3-4b52-8df0-8a6ad6e9f2e2)
- [RFC 3962 AES Encryption for Kerberos 5](https://datatracker.ietf.org/doc/html/rfc3962)
- [impacket Core AD/Kerberos library](https://github.com/fortra/impacket)
- [gMSA Abuse The Hacker Recipes](https://www.thehacker.recipes/ad/movement/credentials/dumping/gmsa)
