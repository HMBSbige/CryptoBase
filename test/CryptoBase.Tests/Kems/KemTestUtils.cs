using CryptoBase.Abstractions.Kems;

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
		byte[] sharedSecret = new byte[T.SharedSecretLength];
		kem.Decapsulate(ciphertext, sharedSecret);
		return sharedSecret;
	}

	// The ciphertext with one bit flipped at every byte position in turn, then all zeros and all ones.
	public static IEnumerable<byte[]> Tampered(byte[] ciphertext)
	{
		for (int i = 0; i < ciphertext.Length; ++i)
		{
			byte[] tampered = (byte[])ciphertext.Clone();
			tampered[i] ^= (byte)(1 << i % 8);
			yield return tampered;
		}

		yield return new byte[ciphertext.Length];
		yield return Enumerable.Repeat((byte)0xFF, ciphertext.Length).ToArray();
	}
}
