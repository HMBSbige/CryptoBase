using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.MLDsa;

namespace CryptoBase.Tests.Signatures;

internal static class SignatureTestUtils
{
	// ISignatureKey cannot make a key, so each type makes its own.
	public static T GenerateKey<T>() where T : class, ISignatureKey<T>
	{
		if (typeof(T) == typeof(MLDsa44))
		{
			return (T)(object)MLDsa44.GenerateKey();
		}

		if (typeof(T) == typeof(MLDsa65))
		{
			return (T)(object)MLDsa65.GenerateKey();
		}

		return typeof(T) == typeof(MLDsa87) ? (T)(object)MLDsa87.GenerateKey() : throw new NotSupportedException(typeof(T).Name);
	}

	public static SignatureAlgorithm[] AlgorithmsOf<T>() where T : class, ISignatureKey<T>
	{
		if (typeof(T) == typeof(MLDsa44))
		{
			return [SignatureAlgorithm.MLDsa44];
		}

		if (typeof(T) == typeof(MLDsa65))
		{
			return [SignatureAlgorithm.MLDsa65];
		}

		return typeof(T) == typeof(MLDsa87) ? [SignatureAlgorithm.MLDsa87] : throw new NotSupportedException(typeof(T).Name);
	}

	public static byte[] ExportSubjectPublicKeyInfo<T>(T key) where T : class, ISignatureKey<T>
	{
		byte[] subjectPublicKeyInfo = new byte[key.SubjectPublicKeyInfoLength];
		key.ExportSubjectPublicKeyInfo(subjectPublicKeyInfo);
		return subjectPublicKeyInfo;
	}

	public static byte[] ExportPkcs8PrivateKey<T>(T key) where T : class, ISignatureKey<T>
	{
		byte[] privateKey = new byte[key.Pkcs8PrivateKeyLength];
		key.ExportPkcs8PrivateKey(privateKey);
		return privateKey;
	}

	public static byte[] Sign<T>(T key, SignatureAlgorithm algorithm, ReadOnlySpan<byte> message) where T : class, ISignatureKey<T>
	{
		byte[] signature = new byte[key.GetMaxSignatureLength(algorithm)];
		int written = key.Sign(algorithm, message, signature);
		return signature.AsSpan(0, written).ToArray();
	}

	// The signature with one bit flipped at a spread of positions, the first and last bytes included.
	public static IEnumerable<byte[]> Tampered(byte[] signature)
	{
		for (int i = 0; i < signature.Length; i += i < 64 ? 1 : 61)
		{
			yield return Flip(signature, i);
		}

		yield return Flip(signature, signature.Length - 1);
	}

	public static byte[] Flip(byte[] source, int index)
	{
		byte[] flipped = (byte[])source.Clone();
		flipped[index] ^= (byte)(1 << index % 8);
		return flipped;
	}
}
