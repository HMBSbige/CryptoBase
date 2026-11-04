using CryptoBase.EllipticCurves.Curve448;

namespace CryptoBase.KeyAgreements.Xdh;

// The private key is any 56 bytes, kept as imported and clamped where it is used; the public key is the canonical u-coordinate that it derives. Keep a key in one writable location and do not copy it: a copy keeps the private key where Clear cannot reach it.
internal struct X448Key
{
	internal const int PrivateKeyLength = 56;
	internal const int PublicKeyLength = 56;
	internal const int SharedSecretLength = 56;

	private InlineArray56<byte> _privateKey;
	private InlineArray56<byte> _publicKey;

	internal bool HasPrivateKey { readonly get; private set; }

	// If drawing the key throws, the key stays as it was.
	[SkipLocalsInit]
	internal void GenerateKey()
	{
		using CryptoBuffer<byte> privateKey = new(stackalloc byte[PrivateKeyLength]);
		SystemRandom.Fill(privateKey.Span);
		SetKey(privateKey.Span);
	}

	internal void ImportPrivateKey(ReadOnlySpan<byte> source)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(source.Length, PrivateKeyLength, nameof(source));

		SetKey(source);
	}

	internal readonly int ExportPrivateKey(Span<byte> destination)
	{
		if (!HasPrivateKey)
		{
			ThrowHelper.ThrowMissingKey("private key");
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, PrivateKeyLength, nameof(destination));

		((ReadOnlySpan<byte>)_privateKey).CopyTo(destination);
		return PrivateKeyLength;
	}

	internal readonly int ExportPublicKey(Span<byte> destination)
	{
		if (!HasPrivateKey)
		{
			ThrowHelper.ThrowMissingKey("public key");
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, PublicKeyLength, nameof(destination));

		((ReadOnlySpan<byte>)_publicKey).CopyTo(destination);
		return PublicKeyLength;
	}

	internal readonly bool TryDeriveSharedSecret(ReadOnlySpan<byte> peerPublicKey, Span<byte> sharedSecret)
	{
		if (!HasPrivateKey)
		{
			ThrowHelper.ThrowMissingKey("private key");
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(sharedSecret.Length, SharedSecretLength, nameof(sharedSecret));

		return TryDeriveSharedSecret(_privateKey, peerPublicKey, sharedSecret);
	}

	internal void Clear()
	{
		_privateKey.ZeroMemory();
		_publicKey.ZeroMemory();
		HasPrivateKey = false;
	}

	// decodeScalar448 of RFC 7748 §5.
	internal static void Clamp(ReadOnlySpan<byte> privateKey, Span<byte> destination)
	{
		Debug.Assert(privateKey.Length is PrivateKeyLength && destination.Length is PrivateKeyLength);

		privateKey.CopyTo(destination);
		destination[0] &= 0xFC;
		destination[PrivateKeyLength - 1] |= 0x80;
	}

	// X448(k, 5) by the fixed-base multiplication on edwards448 and the 4-isogeny of RFC 7748 §4.2, which takes B to u = 5. The product is the identity, which maps to 0, only for the clamped k = 4L, whose X448(k, 5) is 0 as well.
	[SkipLocalsInit]
	internal static void DerivePublicKey(ReadOnlySpan<byte> privateKey, Span<byte> publicKey)
	{
		Debug.Assert(publicKey.Length is PublicKeyLength);

		using CryptoBuffer<byte> scalar = new(stackalloc byte[PrivateKeyLength]);
		Clamp(privateKey, scalar.Span);
		Edwards448.MultiplyBase(scalar.Span, out EdwardsPoint point);
		Edwards448.ToMontgomeryU(in point, publicKey);
		point.ZeroMemory();
	}

	// X448(k, u) into sharedSecret, unless the result is all zeros: then false, with sharedSecret unchanged. The result is zero when the order of the peer point divides 4, or for a point of the curve when k is the clamped 4L; checking the result covers both. The peer key is read in full before sharedSecret is written, so the two may overlap.
	[SkipLocalsInit]
	internal static bool TryDeriveSharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicKey, Span<byte> sharedSecret)
	{
		Debug.Assert(privateKey.Length is PrivateKeyLength && sharedSecret.Length >= SharedSecretLength);

		if (peerPublicKey.Length is not PublicKeyLength)
		{
			return false;
		}

		using CryptoBuffer<byte> scalar = new(stackalloc byte[PrivateKeyLength]);
		using CryptoBuffer<byte> secret = new(stackalloc byte[SharedSecretLength]);
		Clamp(privateKey, scalar.Span);
		Field448.FromBytes(peerPublicKey, out Field448 u);
		Curve448KernelDispatch.Ladder(scalar.Span, in u, out Field448 x, out Field448 z);
		Field448.Invert(in z, out z);
		Field448.Multiply(in x, in z, out x);
		Field448.ToBytes(in x, secret.Span);
		x.ZeroMemory();
		z.ZeroMemory();

		if (IsAllZeros(secret.Span))
		{
			return false;
		}

		secret.Span.CopyTo(sharedSecret);
		return true;
	}

	// Without a branch on the contents.
	private static bool IsAllZeros(ReadOnlySpan<byte> value)
	{
		ulong bits = 0;

		for (int i = 0; i < SharedSecretLength; i += sizeof(ulong))
		{
			bits |= BinaryPrimitives.ReadUInt64LittleEndian(value.Slice(i));
		}

		return bits is 0;
	}

	private void SetKey(ReadOnlySpan<byte> privateKey)
	{
		DerivePublicKey(privateKey, _publicKey);
		privateKey.CopyTo(_privateKey);
		HasPrivateKey = true;
	}
}
