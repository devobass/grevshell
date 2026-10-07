# grevshell

A barebones reverse shell in Go for educational purposes and authorized security testing. A TCP listener executes commands and moves files; a client drives the session over an AES-GCM authenticated channel keyed from a two-way handshake and gated by a shared password. Both sides share one protocol library (`grevcore`).

---

## Legal Notice

**For educational purposes and authorized security testing only.** By downloading, compiling, or running this software you agree that you will use it **only on systems you own, or systems for which you have explicit, documented, written authorization** from the owner — penetration tests, security assessments, CTF competitions, malware analysis coursework, and isolated lab environments. You will not use grevshell to access, modify, exfiltrate data from, or damage any system or network without prior authorization. You accept full and sole responsibility for your use of it, and the author and contributors cannot be held liable for any misuse, damage, data loss, or unlawful activity.

Unlawful use of reverse shell software is a criminal offence in most jurisdictions, and several penalize not just the intrusion but the **production, provisioning, and use** of the tool itself. Commonly engaged laws:

- **Vietnam** — Criminal Code No. 100/2015/QH13 (as amended by Law No. 12/2017/QH14): Art. 286 (producing or **using** tools for unlawful purposes), Art. 289 (unlawfully infiltrating a computer or telecommunications network), Art. 290 (appropriation of property via a network). Also the Law on Prevention and Control of Cyber Attacks on Information Systems (2023), the Law on Network Security No. 86/2015/QH13, and the Law on Cybersecurity No. 116/2025/QH15 **Art. 7** (in force 1 July 2026), which prohibits cyberattacks and the production or use of tools to that effect.
- **United States** — Computer Fraud and Abuse Act (18 U.S.C. § 1030).
- **United Kingdom** — Computer Misuse Act 1990.

If you are unsure whether a use is authorized or lawful in your jurisdiction, **stop and obtain written permission and qualified legal advice first.** Authorization from the system owner is a minimum, not a safe harbour.

---

## Structure

| Path | Role |
| --- | --- |
| `main.go` | Server: flags, listener, authentication, packet dispatch |
| `grevclient/client.go` | Client: flags, authentication, prompt loop, directives |
| `grevcore/encryption.go` | PBKDF2-SHA512 key derivation, AES-GCM encrypt/decrypt |
| `grevcore/headers.go` | `Packet` struct and 8-byte type tags |
| `grevcore/processing.go` | Length-prefixed send/receive, `Assemble`/`Disassemble` |

Every wire message is a `grevcore.Packet` — header tag, filename, payload. The filename field is empty for non-file packets.

---

## Protocol

**Handshake (plaintext, once):** Both peers generate 16 random bytes, exchange them, then XOR the two together to form a 16-byte salt. The shared password is run through PBKDF2-SHA512 (250,000 iterations) with that salt to derive a 16-byte AES key. A wrong password yields a different key, so no packet can be decrypted or authenticated — the password is no longer compared as a plaintext string.

**Framing:** After handshake, every message is length-prefixed (4-byte LE uint32), nonce (12 bytes, GCM default), then AES-GCM ciphertext (which includes the authentication tag). Max packet size: 64 KiB (`0xFFFF`).

**Packet Body:** 8-byte header tag + 2-byte filename length + filename + payload.

Headers: `GREVEXEC` (run command), `GREVRCVF` (upload file), `GREVSNDF` (download file), `GREVAUTH` (legacy, unused).

---

## Build

Requires Go 1.27+ and POSIX host (server executes `/usr/bin/sh`).

```bash
go mod download
go build -o grevshell .            # server
go build -o client ./grevclient    # client
go vet ./...
```

---

## Usage

| Flag | Binary | Default | Meaning |
| --- | --- | --- | --- |
| `-p` | both | `9999` | Port |
| `-k` | both | *(empty)* | Auth password |
| `-h` | client | `localhost` | Server address |

**Server:** `./grevshell -k hunter2`
**Client:** `./client -k hunter2`

Directives: `/SEND <path>`, `/GET <path>`, `/CANCEL`, `/EXIT`. Everything else executes on the server.

---

## Security Notes

Teaching implementation, not a production implant.

- **Unauthenticated handshake** — the 16-byte salt is sent in the clear, so an observer can mount an offline dictionary attack against the password.
- **Arbitrary file access** — `/GET` reads any readable path; `/SEND` overwrites files in server's cwd.
- **No chunking** — files >64 KiB cannot be transferred.
- **Single-threaded** — one session at a time.
- **Text mode only** — no interactive programs or job control.

AES-GCM now authenticates each message, so ciphertext tampering is detected and a bad password cannot send packets. The accept loop survives failed connections (they are closed and skipped).

Hardening: mutual authentication, ECDH key agreement, chunked transfers, command allow-listing.

---

## TODO

- [x] File download/upload (`/GET` and `/SEND`).
- [x] Length-prefixed filenames instead of a fixed 32-byte field.
- [x] Explicit `/EXIT` to end a session.
- [X] Authentication.
- [x] Real cryptography.
- [ ] Secure key exchange.
- [ ] Chunk large files instead of one packet per file.

---

## License

Released under the [ISC License](LICENSE) © 2026 Devobass.
