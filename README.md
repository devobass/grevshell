# grevshell

A barebones reverse shell written in Go, built for educational purposes and
authorized security testing. It demonstrates the core mechanics of a remote
access tool: a TCP listener that executes commands and moves files, a client
that drives the session, and an encrypted channel derived from a shared
handshake.

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
- Typed packets: every request carries an 8-byte magic header that tells the
  server what to do with it
- Shell command execution via `/usr/bin/sh -c`
- File transfer in both directions — `/SEND` uploads to the server, `/GET`
  downloads from it
- Separate `server` (listener) and `client` (controller) binaries
- Shared core library (`grevcore`) so both sides stay in sync
- The server loops back to accepting, so it survives a client disconnecting
- Structured logging via Go's `log/slog`

---

## Project Layout

```
grevshell/
├── main.go                 # Server: listens, accepts, dispatches packets
├── grevclient/
│   └── client.go           # Client: prompt loop, commands, file transfer
├── grevcore/
│   ├── encryption.go       # Key derivation + AES encrypt/decrypt
│   ├── headers.go          # 8-byte packet type tags
│   └── processing.go       # Length-prefixed send/receive framing
└── go.mod
```

---

## Protocol

Every packet on the wire is `[4-byte little-endian length][ciphertext]`, where
the plaintext body always begins with an 8-byte header that selects the
operation (`grevcore/headers.go`):

| Header | Direction | Meaning | Body after the header |
| --- | --- | --- | --- |
| `GREVEXEC` | client → server | Run a shell command | Command line (trimmed) |
| `GREVRCVF` | client → server | Write a file on the server | 32-byte filename + file contents |
| `GREVSNDF` | client → server | Read a file from the server | 32-byte filename |
| `?` | server → client | Reply to an unknown header | `?` |

The server switches on this header (`main.go:64`) and replies to `GREVEXEC`
with the combined stdout/stderr. `GREVRCVF` and `GREVSNDF` are handled
silently, except that a failed file read/write ends the session.

---

## TO-DO

- [x] File download/upload (`/GET` and `/SEND`).
- [ ] Chunk large files instead of sending each one in a single packet.
- [ ] Replace the fixed 32-byte filename field with a length-prefixed one.
- [ ] Add an explicit way to end a session from the client, and stop the
      client looping on stdin EOF.

---

## How It Works

1. **Handshake / key derivation** — Both peers generate 16 random bytes and
   send them over the connection. Each side writes its own seed, reads the
   peer's, and derives the shared session key by XORing both seeds with a
   hardcoded 16-byte seed (`grevcore/encryption.go:16`, used by `DeriveKey`).
2. **Framing** — `SendPacket`/`ReceivePacket` (`grevcore/processing.go`) prefix
   every message with a 4-byte little-endian length header, so the receiver
   knows exactly how much ciphertext to read.
3. **Encryption** — Each packet is AES-CBC encrypted with a fresh random IV
   (prepended to the ciphertext) and PKCS#7 padded.
4. **Dispatch** — The server decrypts the packet, reads the 8-byte type header
   (`GREVEXEC`, `GREVRCVF`, `GREVSNDF`) and branches accordingly. An
   unrecognised header gets a `?` back.
5. **Shell execution** (`GREVEXEC`) — The server runs the command through
   `/usr/bin/sh -c`, captures stdout and stderr into a single buffer, encrypts
   it, and returns it as one framed packet.
6. **Upload** (`GREVRCVF`) — The client sends a 32-byte NUL-padded filename
   followed by the raw file bytes. The server writes it with `filepath.Base`
   and mode `0600`, so the file always lands in the server's working
   directory.
7. **Download** (`GREVSNDF`) — The client sends only the filename. The server
   reads it verbatim and replies with `filename + contents`; the client drops
   the first 32 bytes and writes `filepath.Base(filename)` locally.

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
go build -o client ./grevclient

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
./client
# 2026/... INFO Connecting to 127.0.0.1:9999.
```

The client prints a prompt per command, named after the server's address:

```
127.0.0.1:9999 - $ id
uid=1000(user) gid=1000(user) groups=1000(user)
```

**3. Type commands into the client** — anything that isn't one of the two file
transfer directives is executed on the server and the output is printed back:

```
id
uname -a
whoami
ls -la
```

Type a command and press **Enter** to dispatch it.

**4. Move files in either direction:**

| Directive | Effect |
| --- | --- |
| `/GET <path>` | Read `<path>` on the server, save a copy in the client's working directory |
| `/SEND <path>` | Read `<path>` on the client, write a copy into the server's working directory |

```
127.0.0.1:9999 - $ /SEND notes.txt
127.0.0.1:9999 - $ /GET /etc/hostname
```

Both directives take a single argument, which is split on whitespace, so
paths containing spaces cannot be transferred. The filename field on the wire
is a fixed 32 bytes — longer names are silently truncated.

**5. End the session** — There is no `exit` command; `exit` is simply run
through the shell. Interrupt the client with **Ctrl+C**: the server sees the
dropped connection, closes it, and goes straight back to listening for the
next client. Note that closing stdin instead (**Ctrl+D**) leaves the client
spinning on read errors rather than exiting.

### Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `connection refused` | Server isn't running yet, or the port/addresses don't match |
| Client hangs after connecting | Either peer lost the handshake; restart the client |
| `An error occured while executing the command` | Command not found on the target, or the shell path differs |
| Client panics with `index out of range` | `/GET` or `/SEND` was typed without a filename |
| Client panics after `/GET` | The server could not read the file and closed the connection |
| Uploaded file has a truncated or unexpected name | The filename exceeded the 32-byte field, or it contained spaces |
| `?` printed by the client | The server did not recognise the packet header |

---

## Security Notes & Limitations

This is a teaching implementation, not a production-grade implant. Be aware of
the following before using it in anything resembling a real engagement:

- **Hardcoded, predictable key material.** The XOR derivation seed is embedded
  in the source (`HARDCODED_SEED`), and there is no key exchange, no
  authentication, and no integrity protection. Anyone who can observe the
  handshake can reconstruct the session key.
- **No authentication.** Any host that reaches the listener can issue commands
  *and* move files.
- **Unencrypted control plane.** The listener binds to loopback by default, but
  changing it exposes an unauthenticated RCE endpoint to your network.
- **Unauthenticated file access.** `/GET` reads any path the server process can
  read and returns it verbatim — arbitrary file disclosure with no path
  filtering. `/SEND` writes attacker-supplied content into the server's
  working directory (`filepath.Base` keeps it from escaping that directory,
  but nothing stops an overwrite of an existing file there).
- **Fixed-size filename field.** Filenames travel in a hardcoded 32-byte slot.
  Longer names are truncated, which can silently target the wrong file, and
  names are NUL-trimmed rather than length-checked.
- **No size limits.** A whole file is read, padded and buffered in memory
  before a single packet is sent, and the 4-byte length header is never
  validated — a large or hostile value forces an allocation of
  attacker-controlled size.
- **Short packets are not validated.** The server slices the first 8 bytes of
  every received packet without checking that it is at least that long, so a
  truncated packet panics the process.
- **Text-mode only.** Input is read line by line; interactive/TUI programs,
  job control, and streaming output will not behave correctly.
- **Blocking, one connection at a time.** The server is single-threaded and
  serves one session at a time, then returns to `Accept`, so it is single
  threaded but not single session. The client's own reconnect loop in `main`
  is effectively unreachable, because the request loop never returns.

Hardening ideas for a study exercise: add mutual authentication, use ECDH for
key agreement instead of a hardcoded seed, add an AEAD mode (AES-GCM) to get
integrity checking, validate length headers, bound transfer sizes, and add
command allow-listing.

---

## License

Released under the [ISC License](LICENSE) © 2026 Devobass.
