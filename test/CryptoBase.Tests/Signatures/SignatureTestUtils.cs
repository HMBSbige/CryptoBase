using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.Signatures.MLDsa;
using CryptoBase.Tests.Signatures.Ecdsa;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Signatures;

internal static class SignatureTestUtils
{
	public static readonly KeyType[] KeyTypes =
	[
		new(typeof(MLDsa44), [SignatureAlgorithm.MLDsa44], MLDsa44.GenerateKey),
		new(typeof(MLDsa65), [SignatureAlgorithm.MLDsa65], MLDsa65.GenerateKey),
		new(typeof(MLDsa87), [SignatureAlgorithm.MLDsa87], MLDsa87.GenerateKey),
		new(typeof(EcdsaP256), EcdsaTestUtils.Algorithms, EcdsaP256.GenerateKey),
		new(typeof(EcdsaP384), EcdsaTestUtils.Algorithms, EcdsaP384.GenerateKey),
		new(typeof(EcdsaP521), EcdsaTestUtils.Algorithms, EcdsaP521.GenerateKey),
	];

	public static T GenerateKey<T>() where T : class, ISignatureKey<T>
	{
		return (T)KeyTypeOf<T>().GenerateKey();
	}

	public static SignatureAlgorithm[] AlgorithmsOf<T>() where T : class, ISignatureKey<T>
	{
		return KeyTypeOf<T>().Algorithms;
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

	private static KeyType KeyTypeOf<T>() where T : class, ISignatureKey<T>
	{
		return KeyTypes.FirstOrDefault(static type => type.Type == typeof(T)) ?? throw new NotSupportedException(typeof(T).Name);
	}

	public sealed record KeyType(Type Type, SignatureAlgorithm[] Algorithms, Func<ISignatureKey> GenerateKey);
}
