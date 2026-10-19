# SHAKE CAVP test vectors

NIST Cryptographic Algorithm Validation Program (CAVP) response files for the SHAKE128 and SHAKE256 extendable-output functions (FIPS 202), byte-oriented variant.

- Source: <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/shakebytetestvectors.zip>
- Downloaded: 2026-10-18; SHA-256 of the archive: `debfebc3157b3ceea002b84ca38476420389a3bf7e97dc5f53ea4689a16de4c7`
- Test procedures: [The Secure Hash Algorithm 3 Validation System (SHA3VS)](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf), Sec. 6.3: short messages (6.3.1.2), long messages (6.3.2.2), Monte Carlo (6.3.3) and variable output (6.3.4.2)

| Files | Contents |
| --- | --- |
| `SHAKE*ShortMsg.rsp` | Unchanged: every message length from 0 to twice the rate, in bytes |
| `SHAKE*Monte.rsp` | Unchanged: the message and all 100 Monte Carlo checkpoints |
| `SHAKE*LongMsg.rsp` | Sampled: the header and records 0, 8, 16, …, 96 and 99 (zero-based), 14 of 100 |
| `SHAKE*VariableOut.rsp` | Sampled: the headers, the records whose zero-based index is a multiple of 8, the last record, and the first record with the shortest and with the longest output; 143 of 1126 for SHAKE128, 157 of 1246 for SHAKE256 |

The long-message and variable-output files are sampled to keep the committed vectors under 1 MB in total.
Line endings are normalized to LF, and the sampled files end after their last record; nothing else is edited.

`Len` gives the message length in bits. A record with `Len = 0` writes its empty message as `Msg = 00`, so the message is the first `Len / 8` bytes of `Msg`.
`Outputlen` gives the output length in bits: in a header for ShortMsg and LongMsg, and in each record for VariableOut and Monte.
The variable-output messages have no `Len`; the `[Input Length]` header gives their length in bits.
