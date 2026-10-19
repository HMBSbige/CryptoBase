using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.Benchmark.Hashes.Sha3;

// The benchmark base creates competitors through new(), and the parameterless Sha3Digest is SHA3-256.
public sealed class BouncyCastleSha3_224Digest() : Sha3Digest(224);

public sealed class BouncyCastleSha3_384Digest() : Sha3Digest(384);

public sealed class BouncyCastleSha3_512Digest() : Sha3Digest(512);

public sealed class BouncyCastleShake128Digest() : ShakeDigest(128);

public sealed class BouncyCastleShake256Digest() : ShakeDigest(256);
