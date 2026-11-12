using CryptoBase.Hashes;
using CryptoBase.Hashes.Blake2;
using CryptoBase.Hashes.Blake3;
using CryptoBase.Hashes.Crc32;
using CryptoBase.Hashes.MD5;
using CryptoBase.Hashes.Sha1;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Hashes.Sha3;
using CryptoBase.Hashes.SM3;
using CryptoBase.Platform;

namespace CryptoBase.SpeedTest.Catalog;

internal static partial class AlgorithmCatalog
{
	private static AlgorithmEntry[] CreateHashEntries()
	{
		return
		[
			Hash<HashAlgorithm<MD5Core>>("md5"),
			Hash<HashAlgorithm<Sha1Core>>("sha1"),
			Hash<HashAlgorithm<Sha224Core>>("sha224"),
			Hash<HashAlgorithm<Sha256Core>>("sha256"),
			Hash<PlatformSha256>("platform-sha256"),
			Hash<HashAlgorithm<Sha384Core>>("sha384"),
			Hash<HashAlgorithm<Sha512Core>>("sha512"),
			Hash<HashAlgorithm<Sha3_224Core>>("sha3-224"),
			Hash<HashAlgorithm<Sha3_256Core>>("sha3-256"),
			Hash<HashAlgorithm<Sha3_384Core>>("sha3-384"),
			Hash<HashAlgorithm<Sha3_512Core>>("sha3-512"),
			Hash<HashAlgorithm<SM3Core>>("sm3"),
			Hash<HashAlgorithm<Blake2b256Core>>("blake2b-256"),
			Hash<HashAlgorithm<Blake2b512Core>>("blake2b-512"),
			Hash<Blake3HashAlgorithm>("blake3"),
			Hash<HashAlgorithm<Crc32Core>>("crc32"),
			Hash<HashAlgorithm<Crc32CCore>>("crc32c")
		];
	}

	private static AlgorithmEntry[] CreateXofEntries()
	{
		// The output is as long as SHA3 of the same security strength.
		return
		[
			Xof<Xof<Shake128Core>>("shake128", outputLength: 32),
			Xof<Xof<Shake256Core>>("shake256", outputLength: 64),
			Xof<CShake128Xof>("cshake128", outputLength: 32),
			Xof<CShake256Xof>("cshake256", outputLength: 64)
		];
	}
}
