# SHA-3 CAVP test vectors

NIST Cryptographic Algorithm Validation Program (CAVP) response files for the SHA-3 hash functions (FIPS 202), byte-oriented variant.

- Source: <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha-3bytetestvectors.zip>
- Downloaded: 2026-10-18; SHA-256 of the archive: `cd07701af2e47f5cc889d642528b4bf11f8b6eb55797c7307a96828ed8d8fc8c`
- Test procedures, including the Monte Carlo algorithm: [The Secure Hash Algorithm 3 Validation System (SHA3VS)](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf), Sec. 6.2

| Files | Contents |
| --- | --- |
| `SHA3_*ShortMsg.rsp` | Unchanged: every message length from 0 to the rate, in bytes |
| `SHA3_*Monte.rsp` | Unchanged: the seed and all 100 Monte Carlo checkpoints |
| `SHA3_*LongMsg.rsp` | Sampled: the header and records 0, 8, 16, …, 96 and 99 (zero-based), 14 of 100 |

The long-message files are sampled to keep the committed vectors under 1 MB in total.
Line endings are normalized to LF; nothing else is edited.

`Len` gives the message length in bits. A record with `Len = 0` writes its empty message as `Msg = 00`, so the message is the first `Len / 8` bytes of `Msg`.
