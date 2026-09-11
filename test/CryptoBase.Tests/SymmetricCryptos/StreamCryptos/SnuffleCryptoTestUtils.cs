using CryptoBase.SymmetricCryptos.StreamCryptos;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.SymmetricCryptos.StreamCryptos;

public static class SnuffleCryptoTestUtils
{
	public enum SnuffleAlgorithm
	{
		ChaCha20,
		ChaCha20Original,
		XChaCha20,
		Salsa20,
		XSalsa20
	}

	internal static SnuffleCrypto Create(SnuffleAlgorithm algorithm)
	{
		byte[] key = CreateDeterministicSource(32);

		return algorithm switch
		{
			SnuffleAlgorithm.ChaCha20 => new ChaCha20Crypto(key, CreateDeterministicSource(12)),
			SnuffleAlgorithm.ChaCha20Original => new ChaCha20OriginalCrypto(key, CreateDeterministicSource(8)),
			SnuffleAlgorithm.XChaCha20 => new XChaCha20Crypto(key, CreateDeterministicSource(24)),
			SnuffleAlgorithm.Salsa20 => new Salsa20Crypto(key, CreateDeterministicSource(8)),
			SnuffleAlgorithm.XSalsa20 => new XSalsa20Crypto(key, CreateDeterministicSource(24)),
			_ => throw new ArgumentOutOfRangeException(nameof(algorithm))
		};
	}
}
