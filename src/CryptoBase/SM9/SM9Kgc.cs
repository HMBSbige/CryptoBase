using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.SM9;
using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.SM9;

// The computations of the KGC and the master public keys that GM/T 0044.2 to 0044.4, Sec. 5.3, share: the master private keys in [1, N − 1], the scalars of the user private keys, and the user public keys Q of the encryption master key.
internal static class SM9Kgc
{
	internal const int PrivateKeyLength = 32;

	// The default identifiers hid of the private key generating functions, which the KGC may choose otherwise: those of signatures and encryption as GB/T 41389-2022 gives them, and that of the key exchange as steps A1 and B1 of GM/T 0044.5, B.2, write ID ‖ hid.
	internal const byte SignatureHid = 0x01;
	internal const byte KeyExchangeHid = 0x02;
	internal const byte EncryptionHid = 0x03;

	// A scalar in [1, N − 1] from fill: candidates of 32 bytes until one lies in the range, which rejects 1 − (N − 1)/2^256, about 29%, of them; only that retry branches. If fill throws, nothing is left behind.
	[SkipLocalsInit]
	internal static void GenerateScalar(Action<Span<byte>> fill, out FieldElement<SM9Order> result)
	{
		using CryptoBuffer<byte> candidate = new(stackalloc byte[PrivateKeyLength]);

		do
		{
			fill(candidate.Span);
		}
		while (!FieldElement<SM9Order>.TryImportNonzero(candidate.Span, out result));
	}

	// t2 = k·t1⁻¹ for t1 = H1(ID ‖ hid, N) + k mod N, the scalar of the private key [t2]P1 or [t2]P2 of a user, for the master private key k. GM/T 0044 has the KGC generate a new master key if t1 = 0, which this throws for; only that branches on k.
	[SkipLocalsInit]
	internal static void ExtractScalar(in FieldElement<SM9Order> masterKey, ReadOnlySpan<byte> id, byte hid, out FieldElement<SM9Order> result)
	{
		SM9Hash.H1(id, hid, out FieldElement<SM9Order> t1);
		FieldElement<SM9Order>.Add(in t1, in masterKey, out t1);

		if (FieldElement<SM9Order>.IsZero(in t1) is not 0)
		{
			throw new CryptographicException("The master key cannot give a key for this ID, as H1(ID ‖ hid, N) + k = 0 mod N; generate a new master key, as GM/T 0044 requires.");
		}

		// t1·R inverts to t1⁻¹·R, whose product with the plain k is the plain k·t1⁻¹.
		FieldElement<SM9Order>.ToMontgomery(in t1, out t1);
		FieldElement<SM9Order>.Invert(in t1, out t1);
		FieldElement<SM9Order>.Multiply(in t1, in masterKey, out result);
		t1.ZeroMemory();
	}

	// Q = [H1(ID ‖ hid, N)]P1 + Ppub-e, the public key in G1 of a user of the encryption master public key Ppub-e. Every input is public, so the product takes variable time. Returns false if Q is the point at infinity, for an ID whose t1 is 0, for which no private key exists.
	internal static bool TryGetUserPublicKey(ReadOnlySpan<byte> id, byte hid, in SM9AffinePoint<SM9Fp> masterPublicKey, out SM9AffinePoint<SM9Fp> result)
	{
		SM9Hash.H1(id, hid, out FieldElement<SM9Order> h1);
		return SM9G1.MultiplyBaseAddVariableTime(in h1, in masterPublicKey, out result);
	}

	[DoesNotReturn]
	internal static void ThrowNoKey()
	{
		throw new CryptographicException("No private key exists for this ID under the master public key, as its [H1(ID ‖ hid, N)]P1 + Ppub-e is the point at infinity.");
	}
}
