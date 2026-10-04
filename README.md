# grevshell

A barebones reverse shell written in Go, built for educational purposes and
authorized security testing. It demonstrates the core mechanics of a remote
access tool: a TCP listener that executes commands, a client that drives the
session, and an encrypted channel derived from a shared handshake.

---

## Legal Notice & Disclaimer

**This project is provided for educational purposes and authorized security
testing only.**

By downloading, compiling, or running this software you explicitly agree to all
of the following:

- You will use grevshell **only on systems you own, or systems for which you
  have obtained explicit, documented, and written authorization** from the
  owner. Penetration tests, security assessments, capture-the-flag (CTF)
  competitions, malware analysis coursework, and isolated lab environments are
  permitted uses.
- You will **not** use grevshell to access, modify, exfiltrate data from, or
  damage any system, network, or resource without prior authorization.
- You accept **full and sole responsibility** for how you use this software,
  including any civil, criminal, administrative, or contractual consequences.
- The author and contributors **cannot be held liable** for any misuse,
  damage, data loss, or unlawful activity performed with this software. Use it
  at your own risk.

### Applicable Jurisdictions

Unlawful use of reverse shell software is a criminal offence in most
jurisdictions and can carry severe penalties, including imprisonment. Depending
on where you and your target are located, the following laws are commonly
engaged:

**Vietnam (Socialist Republic of Vietnam)**

Vietnamese law applies particularly strictly to tools of this kind — it
criminalises not only the intrusion itself but also the *production,
provisioning, and use* of tools intended for unlawful purposes:

- **Bộ luật Hình sự (Criminal Code) No. 100/2015/QH13**, as amended by
  Law No. 12/2017/QH14 (effective 1 January 2018):
  - **Article 286** — producing, purchasing, selling, exchanging, donating,
    leasing, providing, or **using** devices, software, tools, or means for
    unlawful purposes.
  - **Article 289** — illegally infiltrating another person's computer network,
    telecommunications network, or electronic device.
  - **Article 290** — appropriating property by means of a computer network,
    telecommunications network, or electronic device.
- **Luật Phòng, chống tấn công vào hệ thống thông tin** (Law on Prevention
  and Control of Cyber Attacks on Information Systems, 2023).
- **Luật An ninh mạng (Law on Network Security) No. 86/2015/QH13**.
- **Luật An ninh mạng (Law on Cybersecurity) No. 116/2025/QH15**, adopted
  10 December 2025 and in force since 1 July 2026, **Article 7** — prohibits
  cyberattacks and the intrusion into, taking control of, disruption or
  destruction of information systems, as well as the **production or use of
  tools, means, or software** to that effect.

**United States** — Computer Fraud and Abuse Act (18 U.S.C. § 1030).

**United Kingdom** — Computer Misuse Act 1990.

If you are unsure whether a use is authorized — or whether it is lawful in
Vietnam or any other jurisdiction — **stop and obtain written permission and
qualified legal advice first.** Authorisation from the network or system owner
is a minimum, not a safe harbour.

---

## Features

- Encrypted command channel (AES-CBC with PKCS#7 padding)
- Session key derived from a two-way random handshake
- Length-prefixed framing for reliable message boundaries
- Separate `server` (listener) and `client` (controller) binaries
- Shared core library (`grevcore`) so both sides stay in sync
- Structured logging via Go's `log/slog`

---

## Project Layout

```
grevshell/
├── main.go            # Server: listens, accepts, executes commands
├── grevclient/
│   └── client.go      # Client: reads stdin, sends commands, prints output
├── grevcore/
│   └── encryption.go  # Key derivation + AES encrypt/decrypt
└── go.mod
```

---

## How It Works

1. **Handshake / key derivation** — Both peers generate 16 random bytes and
   send them over the connection. The shared session key is derived by XORing
   both seeds with a hardcoded 16-byte seed (`grevcore/encryption.go:15`).
2. **Framing** — Every message is prefixed with a 4-byte little-endian length
   header, so the receiver knows exactly how much ciphertext to read.
3. **Encryption** — Each command and each response is AES-CBC encrypted with a
   fresh random IV (prepended to the ciphertext) and PKCS#7 padded.
4. **Execution** — The server decrypts the command, runs it through
   `/usr/bin/sh -c`, captures stdout/stderr, encrypts the combined output, and
   returns it as a single framed message.

---

## Requirements

- Go 1.27.1 or newer
- A POSIX-like system (the server executes `/usr/bin/sh`)

---

## Build

```bash
# fetch dependencies
go mod download

# build both binaries
go build -o grevshell .
go build -o grevclient ./grevclient

# optional: compile-time checks
go vet ./...
```

---

## Usage

> Both binaries currently dial/listen on `localhost:9999`
> (`main.go:19`, `grevclient/client.go:17`). To point at another address, edit
> the address string in each file before building.

**1. Start the server (the listening side):**

```bash
./grevshell
# 2026/... INFO Reverse Shell listening on port 9999.
```

**2. Start the client in a second terminal (the controller side):**

```bash
./grevclient
# 2026/... INFO Connecting to 127.0.0.1:9999.
```

**3. Type commands into the client** — they execute on the server and the
output is printed back:

```
id
uname -a
whoami
```

Type a command and press **Enter** to dispatch it. To close the session, send
the command `exit`.

### Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `connection refused` | Server isn't running yet, or the port/addresses don't match |
| Client hangs after connecting | Either peer lost the handshake; restart the client |
| `An error occured while executing the command` | Command not found on the target, or the shell path differs |

---

## Security Notes & Limitations

This is a teaching implementation, not a production-grade implant. Be aware of
the following before using it in anything resembling a real engagement:

- **Hardcoded, predictable key material.** The XOR derivation seed is embedded
  in the source (`HARDCODED_SEED`), and there is no key exchange, no
  authentication, and no integrity protection. Anyone who can observe the
  handshake can reconstruct the session key.
- **No authentication.** Any host that reaches the listener can issue commands.
- **Unencrypted control plane.** The listener binds to loopback by default, but
  changing it exposes an unauthenticated RCE endpoint to your network.
- **Unchecked reads.** `io.ReadFull` errors and length headers are not validated,
  so a malicious or corrupted peer can crash the server or force an allocation
  of attacker-controlled size.
- **Text-mode only.** Input is read line by line; interactive/TUI programs,
  job control, and streaming output will not behave correctly.
- **Blocking, single session.** The server is single-threaded and handles one
  connection at a time.

Hardening ideas for a study exercise: add mutual authentication, use ECDH for
key agreement instead of a hardcoded seed, add an AEAD mode (AES-GCM) to get
integrity checking, validate length headers, and add command allow-listing.

---

## License

Released under the [ISC License](LICENSE) © 2026 Devobass.