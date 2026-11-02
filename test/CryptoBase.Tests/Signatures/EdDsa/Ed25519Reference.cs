using System.Numerics;
using System.Security.Cryptography;
using static CryptoBase.Tests.EllipticCurves.Curve25519.Curve25519Reference;

namespace CryptoBase.Tests.Signatures.EdDsa;

// The variant of RFC 8032 §5.1: Ed25519, with an empty dom2, or Ed25519ctx and Ed25519ph, whose dom2 holds their phflag.
public enum Ed25519Variant
{
	Pure,
	Context,
	PreHash
}

// Ed25519, Ed25519ctx and Ed25519ph from RFC 8032 §5.1, with BigInteger and the platform's SHA-512, to check the library against. Verification follows the policy of the library: S below L, A decoded strictly, and R compared as bytes with the encoding of [S]B − [k]A.
internal static class Ed25519Reference
{
	internal static byte[] Domain(Ed25519Variant variant, ReadOnlySpan<byte> context)
	{
		return variant switch
		{
			Ed25519Variant.Pure => [],
			Ed25519Variant.Context => [.. "SigEd25519 no Ed25519 collisions"u8, 0, (byte)context.Length, .. context],
			_ => [.. "SigEd25519 no Ed25519 collisions"u8, 1, (byte)context.Length, .. context]
		};
	}

	// The message as the variant signs it, PH(M): SHA-512 for Ed25519ph.
	internal static byte[] Input(Ed25519Variant variant, byte[] message)
	{
		return variant is Ed25519Variant.PreHash ? SHA512.HashData(message) : message;
	}

	// §5.1.5: the pruned first half of SHA-512(seed) and the second half.
	internal static (BigInteger Scalar, byte[] Prefix) Expand(ReadOnlySpan<byte> seed)
	{
		byte[] hash = SHA512.HashData(seed);
		hash[0] &= 0xF8;
		hash[31] = (byte)(hash[31] & 0x7F | 0x40);
		return (DecodeInteger(hash.AsSpan(0, 32)), hash.AsSpan(32).ToArray());
	}

	internal static byte[] PublicKey(ReadOnlySpan<byte> seed)
	{
		return Encode(Multiply(Base, Expand(seed).Scalar));
	}

	// §5.1.6, for the input that Input gives.
	internal static byte[] Sign(ReadOnlySpan<byte> seed, byte[] input, byte[] domain)
	{
		(BigInteger s, byte[] prefix) = Expand(seed);
		byte[] publicKey = Encode(Multiply(Base, s));
		BigInteger r = HashToScalar(domain, prefix, input);
		byte[] encodedR = Encode(Multiply(Base, r));
		BigInteger k = HashToScalar(domain, [.. encodedR, .. publicKey], input);
		return Signature(encodedR, (r + k * s) % L);
	}

	internal static bool Verify(byte[] publicKey, byte[] input, byte[] signature, byte[] domain)
	{
		if (signature.Length is not 64 || Decode(publicKey) is not { } a)
		{
			return false;
		}

		BigInteger s = DecodeInteger(signature.AsSpan(32));
		BigInteger k = HashToScalar(domain, [.. signature.AsSpan(0, 32), .. publicKey], input);
		return s < L && Encode(Add(Multiply(Base, s), Negate(Multiply(a, k)))).AsSpan().SequenceEqual(signature.AsSpan(0, 32));
	}

	// SHA-512(dom2 ‖ prefix ‖ input) mod L, which is r for the prefix of the key and k for R ‖ A.
	internal static BigInteger HashToScalar(byte[] domain, byte[] prefix, byte[] input)
	{
		return DecodeInteger(SHA512.HashData([.. domain, .. prefix, .. input])) % L;
	}

	internal static byte[] Signature(ReadOnlySpan<byte> encodedR, BigInteger s)
	{
		return [.. encodedR, .. EncodeInteger(s)];
	}
}
