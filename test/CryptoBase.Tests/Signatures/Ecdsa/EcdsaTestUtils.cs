using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.Tests.EllipticCurves;
using System.Security.Cryptography;

namespace CryptoBase.Tests.Signatures.Ecdsa;

internal static class EcdsaTestUtils
{
	public static readonly SignatureAlgorithm[] Algorithms = [SignatureAlgorithm.EcdsaSha256, SignatureAlgorithm.EcdsaSha384, SignatureAlgorithm.EcdsaSha512];

	public static CurveCase CurveOf<T>() where T : class, IEcdsa<T>
	{
		return CurveCase.Named(typeof(T).Name switch
		{
			nameof(EcdsaP256) => "secp256r1",
			nameof(EcdsaP384) => "secp384r1",
			nameof(EcdsaP521) => "secp521r1",
			_ => throw new NotSupportedException(typeof(T).Name)
		});
	}

	public static byte[] Hash(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message)
	{
		return algorithm switch
		{
			SignatureAlgorithm.EcdsaSha256 => SHA256.HashData(message),
			SignatureAlgorithm.EcdsaSha384 => SHA384.HashData(message),
			SignatureAlgorithm.EcdsaSha512 => SHA512.HashData(message),
			_ => throw new NotSupportedException(algorithm.ToString())
		};
	}

	public static HashAlgorithmName HashName(SignatureAlgorithm algorithm)
	{
		return algorithm switch
		{
			SignatureAlgorithm.EcdsaSha256 => HashAlgorithmName.SHA256,
			SignatureAlgorithm.EcdsaSha384 => HashAlgorithmName.SHA384,
			SignatureAlgorithm.EcdsaSha512 => HashAlgorithmName.SHA512,
			_ => throw new NotSupportedException(algorithm.ToString())
		};
	}

	public static byte[] ExportPrivateKey<T>(T key) where T : class, IEcdsa<T>
	{
		byte[] privateKey = new byte[T.PrivateKeyLength];
		key.ExportPrivateKey(privateKey);
		return privateKey;
	}

	public static byte[] ExportPublicKey<T>(T key) where T : class, IEcdsa<T>
	{
		byte[] publicKey = new byte[T.PublicKeyLength];
		key.ExportPublicKey(publicKey);
		return publicKey;
	}

	public static int MaxLength<T>(T key, SignatureAlgorithm algorithm, EcdsaSignatureFormat format) where T : class, IEcdsa<T>
	{
		return format is EcdsaSignatureFormat.Der ? key.GetMaxSignatureLength(algorithm) : 2 * T.PrivateKeyLength;
	}

	public static byte[] Sign<T>(T key, SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, ReadOnlySpan<byte> additionalData, EcdsaSignatureFormat format) where T : class, IEcdsa<T>
	{
		byte[] signature = new byte[MaxLength(key, algorithm, format)];
		int written = key.Sign(algorithm, message, additionalData, format, signature);
		return signature.AsSpan(0, written).ToArray();
	}

	public static byte[] SignHash<T>(T key, SignatureAlgorithm algorithm, ReadOnlySpan<byte> hash, ReadOnlySpan<byte> additionalData, EcdsaSignatureFormat format) where T : class, IEcdsa<T>
	{
		byte[] signature = new byte[MaxLength(key, algorithm, format)];
		int written = key.SignHash(algorithm, hash, additionalData, format, signature);
		return signature.AsSpan(0, written).ToArray();
	}
}
