# HPKE test vectors

`hpke-test-vectors.json` gathers known-answer vectors for HPKE (RFC 9180) from three sources. Each vector keeps the field names of its source and adds `source`; each encryption adds `seq`, its sequence number.

| `source` | Origin | Kept |
| --- | --- | --- |
| `RFC 9180` | [`test-vectors.json`](https://github.com/cfrg/draft-irtf-cfrg-hpke/blob/5f503c564da00b0687b3de75f1dfbdfc4079ad31/test-vectors.json) at the commit that RFC 9180, Appendix A cites; SHA-256 `61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6` | Every vector of DHKEM(X25519), DHKEM(X448), DHKEM(P-256) and DHKEM(P-521): all four modes, HKDF-SHA256 and HKDF-SHA512, and all four AEADs, including the export-only one. Encryptions with sequence numbers 0, 1, 2, 4, 255 and 256, as in the appendix |
| `hpke-pq` | [`test-vectors.json`](https://github.com/hpkewg/hpke-pq/blob/11b5b9541e9976fc9ce25902011d20dacc089066/test-vectors.json) of draft-ietf-hpke-pq; SHA-256 `35c59f4a0132e5631e50ac039d8ca3a72e99f5e92dfd94d45338d6ae243f613c` | The KEM values of the DHKEM(P-384, HKDF-SHA384) vector, whose key schedule uses a KDF outside RFC 9180, and the key schedules of the two vectors with HKDF-SHA384 and AES-256-GCM, whose KEMs are ML-KEM-1024 and MLKEM1024-P384 |
| `draft-ietf-hpke-hpke D.n` | Appendix D, Edge-Case Test Vectors, of the [editor's copy of draft-ietf-hpke-hpke](https://github.com/hpkewg/hpke/blob/8668538c220ca19f5513e4cc2b615c589708f3b9/draft-ietf-hpke-hpke.md), dated 29 October 2026 | D.1, a DHKEM(P-256) key pair from the second rejection-sampling candidate, and D.2 to D.5, empty and zero-byte inputs over DHKEM(X25519), in full |

The RFC 9180 vectors of Appendix A.1 to A.7 were checked to equal the JSON entries of the same suites, field by field. The vectors of DHKEM(P-384) and HKDF-SHA384 come from the other sources because the RFC 9180 file has none. Hexadecimal is lowercase; nothing else is edited.
