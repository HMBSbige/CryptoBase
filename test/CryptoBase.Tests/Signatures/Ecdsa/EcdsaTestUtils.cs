using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.Tests.EllipticCurves;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Signatures.Ecdsa;

internal static class EcdsaTestUtils
{
	private const string ECPublicKeyOid = "1.2.840.10045.2.1";

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

	public static byte[] Sign<T>(T key, SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, ReadOnlySpan<byte> additionalData) where T : class, IEcdsa<T>
	{
		byte[] signature = new byte[key.GetMaxSignatureLength(algorithm)];
		int written = key.Sign(algorithm, message, additionalData, signature);
		return signature.AsSpan(0, written).ToArray();
	}

	public static byte[] SignHash<T>(T key, SignatureAlgorithm algorithm, ReadOnlySpan<byte> hash, ReadOnlySpan<byte> additionalData) where T : class, IEcdsa<T>
	{
		byte[] signature = new byte[key.GetMaxSignatureLength(algorithm)];
		int written = key.SignHash(algorithm, hash, additionalData, signature);
		return signature.AsSpan(0, written).ToArray();
	}

	// Encoded here rather than by the code under test, so that r and s may lie outside [1, n − 1].
	public static byte[] DerSignature(BigInteger r, BigInteger s)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);

		using (writer.PushSequence())
		{
			writer.WriteInteger(r);
			writer.WriteInteger(s);
		}

		return writer.Encode();
	}

	public static (BigInteger R, BigInteger S) ReadDerSignature(byte[] signature)
	{
		AsnReader reader = new(signature, AsnEncodingRules.DER);
		AsnReader sequence = reader.ReadSequence();
		BigInteger r = sequence.ReadInteger();
		BigInteger s = sequence.ReadInteger();
		sequence.ThrowIfNotEmpty();
		reader.ThrowIfNotEmpty();
		return (r, s);
	}

	public static byte[] Integer(BigInteger value)
	{
		return Element(0x02, value.ToByteArray(isBigEndian: true));
	}

	// Written here rather than by the code under test.
	public static byte[] Header(byte tag, int length)
	{
		return length switch
		{
			< 0x80 => [tag, (byte)length],
			< 0x100 => [tag, 0x81, (byte)length],
			_ => [tag, 0x82, (byte)(length >> 8), (byte)length]
		};
	}

	public static byte[] Element(byte tag, byte[] contents)
	{
		return [.. Header(tag, contents.Length), .. contents];
	}

	public static byte[] LongForm(byte tag, byte[] contents)
	{
		return contents.Length < 0x80 ? [tag, 0x81, (byte)contents.Length, .. contents] : [tag, 0x82, 0, (byte)contents.Length, .. contents];
	}

	public static byte[] AlgorithmIdentifier(string curveOid)
	{
		return Element(0x30, [.. Oid(ECPublicKeyOid), .. Oid(curveOid)]);
	}

	public static byte[] ECPrivateKey(int version, byte[] d, string? curveOid, byte[]? publicKey, byte[]? trailing = null)
	{
		List<byte> contents = [.. Element(0x02, [(byte)version]), .. Element(0x04, d)];

		if (curveOid is not null)
		{
			contents.AddRange(Element(0xA0, Oid(curveOid)));
		}

		if (publicKey is not null)
		{
			contents.AddRange(Element(0xA1, Element(0x03, [0, .. publicKey])));
		}

		contents.AddRange(trailing ?? []);
		return Element(0x30, [.. contents]);
	}

	public static byte[] Pkcs8(string curveOid, byte[] ecPrivateKey, byte[]? publicKey = null)
	{
		byte[] contents = [.. Element(0x02, [(byte)(publicKey is null ? 0 : 1)]), .. AlgorithmIdentifier(curveOid), .. Element(0x04, ecPrivateKey)];
		return Element(0x30, publicKey is null ? contents : [.. contents, .. Element(0x81, [0, .. publicKey])]);
	}
}
