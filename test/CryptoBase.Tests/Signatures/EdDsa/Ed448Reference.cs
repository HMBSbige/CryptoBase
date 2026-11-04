using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha3;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.Curve448.Curve448Reference;

namespace CryptoBase.Tests.Signatures.EdDsa;

// RFC 8032 §5.2; Ed448ph signs PH(M) = SHAKE256(M, 64).
public enum Ed448Variant
{
	Pure,
	PreHash
}

// Verification follows the policy of the library: S below L, A decoded strictly, and R compared as bytes.
internal static class Ed448Reference
{
	internal const int PreHashLength = 64;

	// dom4(phflag, C) of RFC 8032 §2, which Ed448 has even for an empty context.
	internal static byte[] Domain(Ed448Variant variant, ReadOnlySpan<byte> context)
	{
		return [.. "SigEd448"u8, variant is Ed448Variant.PreHash ? (byte)1 : (byte)0, (byte)context.Length, .. context];
	}

	internal static byte[] Input(Ed448Variant variant, byte[] message)
	{
		return variant is Ed448Variant.PreHash ? Shake256(message, PreHashLength) : message;
	}

	internal static byte[] Shake256(ReadOnlySpan<byte> source, int length)
	{
		byte[] output = new byte[length];
		Xof<Shake256Core>.HashData(source, output);
		return output;
	}

	// RFC 8032 §5.2.5.
	internal static (BigInteger Scalar, byte[] Prefix) Expand(ReadOnlySpan<byte> seed)
	{
		byte[] hash = Shake256(seed, 114);
		hash[0] &= 0xFC;
		hash[55] |= 0x80;
		hash[56] = 0;
		return (DecodeInteger(hash.AsSpan(0, 57)), hash.AsSpan(57).ToArray());
	}

	internal static byte[] PublicKey(ReadOnlySpan<byte> seed)
	{
		return Encode(Multiply(Base, Expand(seed).Scalar));
	}

	// RFC 8032 §5.2.6.
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
		if (signature.Length is not 114 || Decode(publicKey) is not { } a)
		{
			return false;
		}

		BigInteger s = DecodeInteger(signature.AsSpan(57));
		BigInteger k = HashToScalar(domain, [.. signature.AsSpan(0, 57), .. publicKey], input);
		return s < L && Encode(Add(Multiply(Base, s), Negate(Multiply(a, k)))).AsSpan().SequenceEqual(signature.AsSpan(0, 57));
	}

	// r with the prefix of the key, k with R ‖ A.
	internal static BigInteger HashToScalar(byte[] domain, byte[] prefix, byte[] input)
	{
		return DecodeInteger(Shake256([.. domain, .. prefix, .. input], 114)) % L;
	}

	// S may be L or more.
	internal static byte[] Signature(ReadOnlySpan<byte> encodedR, BigInteger s)
	{
		return [.. encodedR, .. EncodeInteger(s, 57)];
	}
}
