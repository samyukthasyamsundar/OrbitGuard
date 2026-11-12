# Threat model

This document says what OrbitGuard's authentication protects against, what it does not, and
which test or experiment backs each claim. It covers the **authenticated mode**
(`--key-file`). Without a key, the link has only a CRC, which detects accidents, not attackers.

## What is being protected

Telemetry flowing from the satellite (sender) to the ground station (receiver) over UDP. The
property that matters is that **the ground station only ever acts on data that came from the
real satellite, once**.

## Attacker model

The attacker **can**: read every packet on the link, send any datagram to the ground
station's UDP port, record and resend packets, modify packets in transit, and send floods.

The attacker **cannot** (assumed): read the shared key, or run code on the satellite or ground
station. If either end is compromised, none of this holds.

## Threats and mitigations

| # | Threat | Mitigation | Evidence |
|---|--------|------------|----------|
| 1 | **Spoofing**: send fake telemetry | Every packet carries a 128-bit HMAC-SHA256 tag over all its bytes; packets without a valid tag are refused | `SecurePacket.WrongKeyIsRejected`, `rogue_sender --attack wrongkey` |
| 2 | **Tampering**: alter a genuine packet | The tag covers the version, key id, counter and every telemetry field | `SecurePacket.EverySingleBitFlipAnywhereIsRejected` (all 424 single-bit changes), `--attack tamper` |
| 3 | **CRC bypass**: tamper and fix the CRC | Authentication, not the CRC, decides acceptance | `SecurePacket.AttackerWhoRecomputesTheCrcStillCannotForge` |
| 4 | **Replay**: resend a captured genuine packet | Strictly increasing counter, with a 64-packet sliding window; repeats are refused | `KeyRing.ReplayedCapturedPacketIsRejected`, `--attack replay` (1 accepted, 24 refused) |
| 5 | **Downgrade**: send unsigned v1 packets to a ground station that expects signing | When a key is configured, unsigned packets are refused, never accepted | `--attack forge` (all refused as "unauthenticated") |
| 6 | **Window manipulation**: use forged packets to advance the replay window | The window only moves for packets that already passed authentication | `SecurePacket.ForgedPacketNeverReachesTheReplayWindow` |
| 7 | **Lockout**: one authentic packet with a huge counter makes every later real packet look stale | A counter may jump ahead by at most one day of ticks; larger jumps are refused and do not move the window | `KeyRing.OneAuthenticPacketWithAHugeCounterCannotLockOutTheRealSender`; reproduced live before the fix (40 of 40 honest packets lost) and fixed after |
| 8 | **Timing side channel** on tag comparison | Constant-time comparison | `ConstantTimeEqual` (checks every byte position); not measured for timing |
| 9 | **Malformed input** crashing the receiver | Strict bounds-checked decoding; invalid data counted, never fatal | codec/recording tests; sanitizer builds clean; `--attack flood` |
| 10 | **Key theft from disk** | The key file must be mode 600 or the program refuses to start; keys are never taken from the command line (they would leak via the process list and shell history) | `KeyFile.RefusesGroupOrWorldAccessibleFile` |

## What this does **not** protect against

- **Confidentiality.** Telemetry is authenticated, not encrypted. Anyone on the link can read it.
- **A stolen or leaked key.** The key is shared and symmetric, so whoever has it can forge
  packets and the receiver cannot tell them from real ones. There is no per-device identity
  and no revocation beyond removing a key id from the receiver.
- **Poisoned first packet.** The first counter seen for a key sets the baseline. If an attacker
  with a validly signed packet carrying a huge counter reaches the ground station *before the
  real satellite*, the baseline is wrong and the real satellite is locked out until the ground
  station restarts. Reproduced in testing. Closing it needs state outside the protocol, such
  as a persisted counter or a trusted clock. Note the attacker needs a *genuinely signed* packet,
  so this requires either the key or a faulty real sender.
- **Denial of service.** A flood cannot make the receiver accept anything, but it can still
  consume CPU and fill the UDP buffer, causing real packets to be dropped. There is no rate
  limiting yet.
- **Traffic analysis.** Packet timing and size are visible.
- **Clock-derived counter.** The simulator seeds its counter from wall-clock time so it keeps
  rising across restarts. A satellite whose clock jumps backwards would reuse low values and
  be refused. Flight hardware would use a nonvolatile counter.
- **The dashboard.** It has no login and relies on being bound to localhost.
- **Compromised endpoints.** Out of scope.

## About the cryptography

SHA-256 and HMAC are implemented in this repository from the published standards and checked
against the official test vectors (FIPS 180-4 / NIST, RFC 4231) and an independent
implementation. **This is a learning implementation.** It has not been audited, and
production code should use a vetted library such as libsodium or OpenSSL. The 128-bit tag
truncation follows common practice (RFC 2104 permits it) but is a deliberate size/overhead
trade-off.

## How the tests were checked

The security tests were validated by mutation: the code was deliberately broken in five ways
(tag check removed, tag half-checked, tag not covering the counter, window advancing before
authentication, window off by one) and each was caught by at least one test. One earlier gap
was found this way (an HMAC key-length boundary) and closed with a new test.
