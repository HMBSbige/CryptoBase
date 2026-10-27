using CryptoBase.Abstractions.Kems;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Kems;

internal static class KemTestUtils
{
	public static byte[] ExportPrivateSeed<T>(T kem) where T : class, IKem<T>
	{
		byte[] seed = new byte[T.PrivateSeedLength];
		kem.ExportPrivateSeed(seed);
		return seed;
	}

	public static byte[] ExportDecapsulationKey<T>(T kem) where T : class, IKem<T>
	{
		byte[] decapsulationKey = new byte[T.DecapsulationKeyLength];
		kem.ExportDecapsulationKey(decapsulationKey);
		return decapsulationKey;
	}

	public static byte[] ExportEncapsulationKey<T>(T kem) where T : class, IKem<T>
	{
		byte[] encapsulationKey = new byte[T.EncapsulationKeyLength];
		kem.ExportEncapsulationKey(encapsulationKey);
		return encapsulationKey;
	}

	public static (byte[] Ciphertext, byte[] SharedSecret) Encapsulate<T>(T kem) where T : class, IKem<T>
	{
		byte[] ciphertext = new byte[T.CiphertextLength];
		byte[] sharedSecret = new byte[T.SharedSecretLength];
		kem.Encapsulate(ciphertext, sharedSecret);
		return (ciphertext, sharedSecret);
	}

	public static byte[] Decapsulate<T>(T kem, ReadOnlySpan<byte> ciphertext) where T : class, IKem<T>
	{
		(bool result, byte[] sharedSecret) = TryDecapsulate(kem, ciphertext);

		if (!result)
		{
			Assert.Fail("TryDecapsulate returned false.");
		}

		return sharedSecret;
	}

	// Output starts filled with DestinationSentinel, so a false result can be checked to leave it unchanged.
	public static (bool Result, byte[] Output) TryDecapsulate<T>(T kem, ReadOnlySpan<byte> ciphertext) where T : class, IKem<T>
	{
		byte[] output = CreateGuardedBuffer(0, T.SharedSecretLength, 0);
		bool result = kem.TryDecapsulate(ciphertext, output);
		return (result, output);
	}

	// The ciphertext with one bit flipped at every byte position in turn, then all zeros and all ones.
	public static IEnumerable<byte[]> Tampered(byte[] ciphertext)
	{
		for (int i = 0; i < ciphertext.Length; ++i)
		{
			yield return Flip(ciphertext, i);
		}

		yield return new byte[ciphertext.Length];
		yield return Enumerable.Repeat((byte)0xFF, ciphertext.Length).ToArray();
	}
}
