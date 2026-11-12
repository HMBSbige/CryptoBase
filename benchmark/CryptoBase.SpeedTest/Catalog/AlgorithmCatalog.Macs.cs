using CryptoBase.Hashes.Blake2;
using CryptoBase.Hashes.MD5;
using CryptoBase.Hashes.Sha1;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Hashes.Sha3;
using CryptoBase.Hashes.SM3;
using CryptoBase.Macs.Hmac;
using CryptoBase.Macs.Kmac;
using CryptoBase.Macs.Poly1305;
using CryptoBase.Platform;

namespace CryptoBase.SpeedTest.Catalog;

internal static partial class AlgorithmCatalog
{
	private static AlgorithmEntry[] CreateMacEntries()
	{
		return
		[
			Mac<HmacAlgorithm<MD5Core>>("hmac-md5", keySize: 32),
			Mac<HmacAlgorithm<Sha1Core>>("hmac-sha1", keySize: 32),
			Mac<HmacAlgorithm<Sha224Core>>("hmac-sha224", keySize: 32),
			Mac<HmacAlgorithm<Sha256Core>>("hmac-sha256", keySize: 32),
			Mac<HmacAlgorithm<Sha384Core>>("hmac-sha384", keySize: 32),
			Mac<HmacAlgorithm<Sha512Core>>("hmac-sha512", keySize: 32),
			Mac<HmacAlgorithm<Sha3_224Core>>("hmac-sha3-224", keySize: 32),
			Mac<HmacAlgorithm<Sha3_256Core>>("hmac-sha3-256", keySize: 32),
			Mac<HmacAlgorithm<Sha3_384Core>>("hmac-sha3-384", keySize: 32),
			Mac<HmacAlgorithm<Sha3_512Core>>("hmac-sha3-512", keySize: 32),
			Mac<HmacAlgorithm<SM3Core>>("hmac-sm3", keySize: 32),
			Mac<HmacAlgorithm<Blake2b256Core>>("hmac-blake2b-256", keySize: 32),
			Mac<HmacAlgorithm<Blake2b512Core>>("hmac-blake2b-512", keySize: 32),
			Mac<Poly1305Algorithm>("poly1305", keySize: 32),
			Mac<Kmac128Algorithm>("kmac128", keySize: 32, macLength: 32, Kmac128Algorithm.Mac),
			Mac<Kmac256Algorithm>("kmac256", keySize: 32, macLength: 64, Kmac256Algorithm.Mac),
			Mac<KmacXof128Algorithm>("kmacxof128", keySize: 32, macLength: 32, KmacXof128Algorithm.HashData),
			Mac<KmacXof256Algorithm>("kmacxof256", keySize: 32, macLength: 64, KmacXof256Algorithm.HashData),
			Mac<PlatformHmacSha256>("platform-hmac-sha256", keySize: 32)
		];
	}
}
