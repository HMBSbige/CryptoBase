#pragma warning disable SYSLIB5006

using CryptoBase.Signatures.MLDsa;
using CryptoBase.Tests.Hashes.Sha3;
using System.Security.Cryptography;
using BclMLDsa = System.Security.Cryptography.MLDsa;

namespace CryptoBase.Tests.Signatures.MLDsa;

internal static class MLDsaTestUtils
{
	// The DER encoding of 2.16.840.1.101.3.4.2.x without its last byte, x (FIPS 204, Sec. 5.4).
	private static ReadOnlySpan<byte> HashOidPrefix => [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02];

	public static byte[] ExportPrivateSeed<T>(T key) where T : class, IMLDsa<T>
	{
		byte[] seed = new byte[T.PrivateSeedLength];
		key.ExportPrivateSeed(seed);
		return seed;
	}

	public static byte[] ExportPrivateKey<T>(T key) where T : class, IMLDsa<T>
	{
		byte[] privateKey = new byte[T.PrivateKeyLength];
		key.ExportPrivateKey(privateKey);
		return privateKey;
	}

	public static byte[] ExportPublicKey<T>(T key) where T : class, IMLDsa<T>
	{
		byte[] publicKey = new byte[T.PublicKeyLength];
		key.ExportPublicKey(publicKey);
		return publicKey;
	}

	public static byte[] Sign<T>(T key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> context = default) where T : class, IMLDsa<T>
	{
		byte[] signature = new byte[T.SignatureLength];
		key.Sign(message, signature, context);
		return signature;
	}

	public static byte[] SignPreHash<T>(T key, ReadOnlySpan<byte> hash, string hashAlgorithmOid, ReadOnlySpan<byte> context = default) where T : class, IMLDsa<T>
	{
		byte[] signature = new byte[T.SignatureLength];
		key.SignPreHash(hash, signature, hashAlgorithmOid, context);
		return signature;
	}

	public static byte[] SignMu<T>(T key, ReadOnlySpan<byte> mu) where T : class, IMLDsa<T>
	{
		byte[] signature = new byte[T.SignatureLength];
		key.SignMu(mu, signature);
		return signature;
	}

	// ML-DSA.Sign with a chosen rnd, which IMLDsa does not expose.
	public static byte[] SignWithRandomness<T>(T key, ReadOnlySpan<byte> message, ReadOnlySpan<byte> context, ReadOnlySpan<byte> randomness) where T : class, IMLDsa<T>
	{
		byte[] signature = new byte[T.SignatureLength];

		switch (key)
		{
			case MLDsa44 mlDsa44:
			{
				mlDsa44.Sign(message, context, randomness, signature);
				break;
			}
			case MLDsa65 mlDsa65:
			{
				mlDsa65.Sign(message, context, randomness, signature);
				break;
			}
			case MLDsa87 mlDsa87:
			{
				mlDsa87.Sign(message, context, randomness, signature);
				break;
			}
			default:
			{
				throw new NotSupportedException(typeof(T).Name);
			}
		}

		return signature;
	}

	// ML-DSA.Sign_internal after μ with a chosen rnd, which IMLDsa does not expose.
	public static byte[] SignMuWithRandomness<T>(T key, ReadOnlySpan<byte> mu, ReadOnlySpan<byte> randomness) where T : class, IMLDsa<T>
	{
		byte[] signature = new byte[T.SignatureLength];

		switch (key)
		{
			case MLDsa44 mlDsa44:
			{
				mlDsa44.SignMu(mu, randomness, signature);
				break;
			}
			case MLDsa65 mlDsa65:
			{
				mlDsa65.SignMu(mu, randomness, signature);
				break;
			}
			case MLDsa87 mlDsa87:
			{
				mlDsa87.SignMu(mu, randomness, signature);
				break;
			}
			default:
			{
				throw new NotSupportedException(typeof(T).Name);
			}
		}

		return signature;
	}

	// μ = H(H(pk, 64) ‖ M′, 64) for the M′ of ML-DSA (Algorithm 2), from the reference sponge.
	public static byte[] Mu(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> message, ReadOnlySpan<byte> context = default)
	{
		return MuOfFormattedMessage(publicKey, [0, (byte)context.Length, .. context, .. message]);
	}

	// μ for the M′ of HashML-DSA (Algorithm 4), with hashArc the last arc of the OID of the hash.
	public static byte[] PreHashMu(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> hash, byte hashArc, ReadOnlySpan<byte> context = default)
	{
		return MuOfFormattedMessage(publicKey, [1, (byte)context.Length, .. context, .. HashOidPrefix, hashArc, .. hash]);
	}

	// k, l, η and λ of FIPS 204, Table 1; λ is also the collision strength in bits that a pre-hash needs.
	public static (int K, int L, int Eta, int Lambda) Parameters<T>() where T : class, IMLDsa<T>
	{
		if (typeof(T) == typeof(MLDsa44))
		{
			return (4, 4, 2, 128);
		}

		if (typeof(T) == typeof(MLDsa65))
		{
			return (6, 5, 4, 192);
		}

		return typeof(T) == typeof(MLDsa87) ? (8, 7, 2, 256) : throw new NotSupportedException(typeof(T).Name);
	}

	// id-ml-dsa-44, -65 or -87 (2.16.840.1.101.3.4.3.17 to 19) with absent parameters, in DER.
	public static byte[] AlgorithmIdentifier<T>() where T : class, IMLDsa<T>
	{
		byte arc = Parameters<T>().K switch
		{
			4 => 17,
			6 => 18,
			_ => 19
		};

		return [0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03, arc];
	}

	public static MLDsaAlgorithm BclAlgorithm<T>() where T : class, IMLDsa<T>
	{
		if (typeof(T) == typeof(MLDsa44))
		{
			return MLDsaAlgorithm.MLDsa44;
		}

		if (typeof(T) == typeof(MLDsa65))
		{
			return MLDsaAlgorithm.MLDsa65;
		}

		return typeof(T) == typeof(MLDsa87) ? MLDsaAlgorithm.MLDsa87 : throw new NotSupportedException(typeof(T).Name);
	}

	public static void SkipUnlessSupported()
	{
		if (!BclMLDsa.IsSupported)
		{
			Skip.Test("The platform does not support ML-DSA.");
		}
	}

	private static byte[] MuOfFormattedMessage(ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> formattedMessage)
	{
		byte[] tr = Shake256(publicKey, 64);
		return Shake256([.. tr, .. formattedMessage], 64);
	}

	private static byte[] Shake256(ReadOnlySpan<byte> message, int length)
	{
		return KeccakReference.Sponge(message, 136, 0x1F, length);
	}
}
