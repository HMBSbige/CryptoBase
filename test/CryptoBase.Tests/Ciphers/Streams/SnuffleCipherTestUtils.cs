using CryptoBase.Ciphers.Streams;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Streams;

public static class SnuffleCipherTestUtils
{
	public static IEnumerable<SnuffleCase> CipherCases()
	{
		yield return new SnuffleCase("ChaCha20", static () => new ChaCha20Cipher(CreateDeterministicSource(ChaCha20Cipher.KeySize), CreateDeterministicSource(ChaCha20Cipher.IVSize)), uint.MaxValue);
		yield return new SnuffleCase("ChaCha20Original", static () => new ChaCha20OriginalCipher(CreateDeterministicSource(32), CreateDeterministicSource(ChaCha20OriginalCipher.IVSize)), ulong.MaxValue);
		yield return new SnuffleCase("XChaCha20", static () => new XChaCha20Cipher(CreateDeterministicSource(XChaCha20Cipher.KeySize), CreateDeterministicSource(XChaCha20Cipher.IVSize)), ulong.MaxValue);
		yield return new SnuffleCase("Salsa20", static () => new Salsa20Cipher(CreateDeterministicSource(32), CreateDeterministicSource(Salsa20Cipher.IVSize)), ulong.MaxValue);
		yield return new SnuffleCase("XSalsa20", static () => new XSalsa20Cipher(CreateDeterministicSource(XSalsa20Cipher.KeySize), CreateDeterministicSource(XSalsa20Cipher.IVSize)), ulong.MaxValue);
	}

	public static void SetCounter(SnuffleCipher crypto, ulong counter)
	{
		switch (crypto)
		{
			case ChaCha20Cipher chaCha20:
			{
				chaCha20.SetCounter(checked((uint)counter));
				break;
			}
			case Salsa20Cipher salsa20:
			{
				salsa20.SetCounter(counter);
				break;
			}
			case ChaCha20OriginalCipher chaCha20Original:
			{
				chaCha20Original.SetCounter(counter);
				break;
			}
			default:
			{
				throw new ArgumentOutOfRangeException(nameof(crypto));
			}
		}
	}
}
