using CryptoBase.EllipticCurves.Curve448;

namespace CryptoBase.KeyAgreements.Xdh;

// The private key is any 56 bytes, kept as imported and clamped where it is used. The public key is a u-coordinate: canonical where the key derives it, the bytes as given where it was imported alone. Keep a key in one writable location and do not copy it: a copy keeps the private key where Clear cannot reach it.
internal struct X448Key : IDiffieHellmanKey<X448Key>
{
	internal const int PrivateKeyLength = 56;
	internal const int PublicKeyLength = 56;
	internal const int SharedSecretLength = 56;

	private InlineArray56<byte> _privateKey;
	private InlineArray56<byte> _publicKey;

	internal bool HasPrivateKey { readonly get; private set; }

	// Set whenever HasPrivateKey is.
	internal bool HasPublicKey { readonly get; private set; }

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
		if (!HasPublicKey)
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
		HasPublicKey = false;
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

		if (FixedTime.Accumulate(secret.Span) is 0)
		{
			return false;
		}

		secret.Span.CopyTo(sharedSecret);
		return true;
	}

	// X448(k, 5) into publicKey and X448(k, u) into sharedSecret, for a peer key not of small order, with one inversion: 1/(X·z) gives 1/X for the isogeny u = (Y/X)² and 1/z for the ladder. Unless k is the clamped 4L, neither factor is 0: X is 0 only for the identity, and z only if L | k on the curve or L' | k on the twist, whose prime L' > 2^446 divides no clamped k. For 4L, false, with neither buffer written.
	[SkipLocalsInit]
	internal static bool TryDerivePublicKeyAndSharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicKey, Span<byte> publicKey, Span<byte> sharedSecret)
	{
		Debug.Assert(peerPublicKey.Length is PublicKeyLength && publicKey.Length is PublicKeyLength && sharedSecret.Length is SharedSecretLength);

		using CryptoBuffer<byte> scalar = new(stackalloc byte[PrivateKeyLength]);
		Clamp(privateKey, scalar.Span);
		Edwards448.MultiplyBase(scalar.Span, out EdwardsPoint point);
		Field448.FromBytes(peerPublicKey, out Field448 u);
		Curve448KernelDispatch.Ladder(scalar.Span, in u, out Field448 x, out Field448 z);
		bool valid = Field448.IsZero(in point.X) is 0;
		Field448.Multiply(in point.X, in z, out Field448 inverse);
		Field448.Invert(in inverse, out inverse);
		Field448.Multiply(in inverse, in z, out z);
		Field448.Multiply(in inverse, in point.X, out inverse);
		Field448.Multiply(in point.Y, in z, out z);
		Field448.Square(in z, out z);
		Field448.Multiply(in x, in inverse, out x);

		if (valid)
		{
			Field448.ToBytes(in z, publicKey);
			Field448.ToBytes(in x, sharedSecret);
		}

		point.ZeroMemory();
		x.ZeroMemory();
		z.ZeroMemory();
		inverse.ZeroMemory();
		return valid;
	}

	// As TryDerivePublicKeyAndSharedSecret, with X448(s, u) for AuthEncap's sender key s after X448(k, u) in sharedSecrets; 1/(X·z·z') gives all three inverses. z' is not 0, as the clamped s of a private key is not 4L.
	[SkipLocalsInit]
	internal static bool TryDerivePublicKeyAndSharedSecrets(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> senderPrivateKey, ReadOnlySpan<byte> peerPublicKey, Span<byte> publicKey, Span<byte> sharedSecrets)
	{
		Debug.Assert(senderPrivateKey.Length is PrivateKeyLength && peerPublicKey.Length is PublicKeyLength && publicKey.Length is PublicKeyLength && sharedSecrets.Length is 2 * SharedSecretLength);

		using CryptoBuffer<byte> scalar = new(stackalloc byte[PrivateKeyLength]);
		Clamp(privateKey, scalar.Span);
		Edwards448.MultiplyBase(scalar.Span, out EdwardsPoint point);
		Field448.FromBytes(peerPublicKey, out Field448 u);
		Curve448KernelDispatch.Ladder(scalar.Span, in u, out Field448 x, out Field448 z);
		Clamp(senderPrivateKey, scalar.Span);
		Curve448KernelDispatch.Ladder(scalar.Span, in u, out Field448 senderX, out Field448 senderZ);
		bool valid = Field448.IsZero(in point.X) is 0;
		Field448.Multiply(in point.X, in z, out Field448 product);
		Field448.Multiply(in product, in senderZ, out Field448 inverse);
		Field448.Invert(in inverse, out inverse);
		Field448.Multiply(in inverse, in product, out product);
		Field448.Multiply(in senderX, in product, out senderX);
		Field448.Multiply(in inverse, in senderZ, out inverse);
		Field448.Multiply(in inverse, in z, out z);
		Field448.Multiply(in inverse, in point.X, out inverse);
		Field448.Multiply(in point.Y, in z, out z);
		Field448.Square(in z, out z);
		Field448.Multiply(in x, in inverse, out x);

		if (valid)
		{
			Field448.ToBytes(in z, publicKey);
			Field448.ToBytes(in x, sharedSecrets.Slice(0, SharedSecretLength));
			Field448.ToBytes(in senderX, sharedSecrets.Slice(SharedSecretLength));
		}

		point.ZeroMemory();
		x.ZeroMemory();
		z.ZeroMemory();
		senderX.ZeroMemory();
		senderZ.ZeroMemory();
		product.ZeroMemory();
		inverse.ZeroMemory();
		return valid;
	}

	// X448(k, u) ‖ X448(k, u') into sharedSecrets, for a sender key u' not of small order, unless the first is all zeros: then false, with sharedSecrets unchanged. 1/(z·z') gives both inverses; z = 0, the one way for the first to fail, zeroes both results, and z' is not 0, as in TryDerivePublicKeyAndSharedSecret. The peer key is read in full before sharedSecrets is written, so the two may overlap.
	[SkipLocalsInit]
	internal static bool TryDeriveSharedSecrets(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicKey, ReadOnlySpan<byte> senderPublicKey, Span<byte> sharedSecrets)
	{
		Debug.Assert(privateKey.Length is PrivateKeyLength && senderPublicKey.Length is PublicKeyLength && sharedSecrets.Length >= 2 * SharedSecretLength);

		if (peerPublicKey.Length is not PublicKeyLength)
		{
			return false;
		}

		using CryptoBuffer<byte> scalar = new(stackalloc byte[PrivateKeyLength]);
		using CryptoBuffer<byte> secrets = new(stackalloc byte[2 * SharedSecretLength]);
		Clamp(privateKey, scalar.Span);
		Field448.FromBytes(peerPublicKey, out Field448 u);
		Curve448KernelDispatch.Ladder(scalar.Span, in u, out Field448 x, out Field448 z);
		Field448.FromBytes(senderPublicKey, out u);
		Curve448KernelDispatch.Ladder(scalar.Span, in u, out Field448 senderX, out Field448 senderZ);
		Field448.Multiply(in z, in senderZ, out Field448 inverse);
		Field448.Invert(in inverse, out inverse);
		Field448.Multiply(in inverse, in senderZ, out senderZ);
		Field448.Multiply(in inverse, in z, out z);
		Field448.Multiply(in x, in senderZ, out x);
		Field448.Multiply(in senderX, in z, out senderX);
		Field448.ToBytes(in x, secrets.Span.Slice(0, SharedSecretLength));
		Field448.ToBytes(in senderX, secrets.Span.Slice(SharedSecretLength));
		x.ZeroMemory();
		z.ZeroMemory();
		senderX.ZeroMemory();
		senderZ.ZeroMemory();
		inverse.ZeroMemory();

		if (FixedTime.Accumulate(secrets.Span.Slice(0, SharedSecretLength)) is 0)
		{
			return false;
		}

		secrets.Span.CopyTo(sharedSecrets);
		return true;
	}

	// The DHKEM view of the key. Every 56-byte string is a private key, exported as imported, except those whose clamped value is 4L. A public key comes from TryImportPublicKey, which rejects the points of small order, or from a private key, so the shared secrets below are never all zeros.
	static int IDiffieHellmanKey<X448Key>.PrivateKeyLength => PrivateKeyLength;

	static int IDiffieHellmanKey<X448Key>.PublicKeyLength => PublicKeyLength;

	static int IDiffieHellmanKey<X448Key>.SharedSecretLength => SharedSecretLength;

	static bool IDiffieHellmanKey<X448Key>.ClampsPrivateKey => true;

	static byte IDiffieHellmanKey<X448Key>.PrivateKeyMask => 0xFF;

	readonly bool IDiffieHellmanKey<X448Key>.HasPrivateKey => HasPrivateKey;

	readonly bool IDiffieHellmanKey<X448Key>.HasPublicKey => HasPublicKey;

	// The clamped 4L is the one private key whose public key is 0.
	bool IDiffieHellmanKey<X448Key>.TryImportPrivateKey(ReadOnlySpan<byte> source)
	{
		if (source.Length is PrivateKeyLength)
		{
			SetKey(source);

			if (FixedTime.Accumulate(_publicKey) is not 0)
			{
				return true;
			}
		}

		Clear();
		return false;
	}

	// For a key that is used without a private key, as an encapsulation key is: false, with the key cleared, for the wrong length or a point whose shared secret is all zeros with every private key. The encoding is kept as given.
	bool IDiffieHellmanKey<X448Key>.TryImportPublicKey(ReadOnlySpan<byte> source)
	{
		Clear();

		if (source.Length is not PublicKeyLength || IsSmallOrder(source))
		{
			return false;
		}

		source.CopyTo(_publicKey);
		HasPublicKey = true;
		return true;
	}

	// Unclamped, as draft-ietf-hpke-hpke serializes it; RFC 9180, Sec. 7.1.2 clamps it instead, which gives the same key.
	readonly int IDiffieHellmanKey<X448Key>.ExportPrivateKey(Span<byte> destination)
	{
		return ExportPrivateKey(destination);
	}

	readonly int IDiffieHellmanKey<X448Key>.ExportPublicKey(Span<byte> destination)
	{
		return ExportPublicKey(destination);
	}

	readonly bool IDiffieHellmanKey<X448Key>.TryDeriveSharedSecret(ReadOnlySpan<byte> peerPublicKey, Span<byte> sharedSecret)
	{
		return TryDeriveSharedSecret(peerPublicKey, sharedSecret);
	}

	static void IDiffieHellmanKey<X448Key>.DeriveSharedSecret(in X448Key privateKey, in X448Key publicKey, Span<byte> destination)
	{
		Debug.Assert(privateKey.HasPrivateKey && publicKey.HasPublicKey);

		bool derived = TryDeriveSharedSecret(privateKey._privateKey, publicKey._publicKey, destination.Slice(0, SharedSecretLength));
		Debug.Assert(derived);
	}

	// A key clamped to 4L, drawn with probability 2^−445, is drawn again; the branch reveals only that a discarded key was bad.
	[SkipLocalsInit]
	static void IDiffieHellmanKey<X448Key>.GenerateEphemeral(in X448Key publicKey, Span<byte> ephemeralPublicKey, Span<byte> sharedSecret)
	{
		Debug.Assert(publicKey.HasPublicKey);

		using CryptoBuffer<byte> ephemeral = new(stackalloc byte[PrivateKeyLength]);

		do
		{
			SystemRandom.Fill(ephemeral.Span);
		}
		while (!TryDerivePublicKeyAndSharedSecret(ephemeral.Span, publicKey._publicKey, ephemeralPublicKey.Slice(0, PublicKeyLength), sharedSecret.Slice(0, SharedSecretLength)));
	}

	// As GenerateEphemeral, with the sender's shared secret after the ephemeral one, from the same inversion.
	[SkipLocalsInit]
	static void IDiffieHellmanKey<X448Key>.GenerateEphemeral(in X448Key publicKey, in X448Key sender, Span<byte> ephemeralPublicKey, Span<byte> sharedSecrets)
	{
		Debug.Assert(publicKey.HasPublicKey && sender.HasPrivateKey);

		using CryptoBuffer<byte> ephemeral = new(stackalloc byte[PrivateKeyLength]);

		do
		{
			SystemRandom.Fill(ephemeral.Span);
		}
		while (!TryDerivePublicKeyAndSharedSecrets(ephemeral.Span, sender._privateKey, publicKey._publicKey, ephemeralPublicKey.Slice(0, PublicKeyLength), sharedSecrets.Slice(0, 2 * SharedSecretLength)));
	}

	static bool IDiffieHellmanKey<X448Key>.TryDeriveSharedSecrets(ref X448Key privateKey, ReadOnlySpan<byte> peerPublicKey, in X448Key publicKey, Span<byte> sharedSecrets)
	{
		Debug.Assert(privateKey.HasPrivateKey && publicKey.HasPublicKey);

		return TryDeriveSharedSecrets(privateKey._privateKey, peerPublicKey, publicKey._publicKey, sharedSecrets);
	}

	void IDiffieHellmanKey<X448Key>.Clear()
	{
		Clear();
	}

	// Whether every shared secret with publicKey is all zeros: [4]P is the point at infinity, which holds just for u = 0 and u = ±1, as u² + Au + 1 has no root. The test is u³ − u = 0 on the reduced u, in constant time.
	private static bool IsSmallOrder(ReadOnlySpan<byte> publicKey)
	{
		Debug.Assert(publicKey.Length is PublicKeyLength);

		Field448.FromBytes(publicKey, out Field448 u);
		Field448.Square(in u, out Field448 product);
		Field448.Subtract(in product, in Field448.One, out product);
		Field448.Multiply(in u, in product, out product);
		return Field448.IsZero(in product) is not 0;
	}

	private void SetKey(ReadOnlySpan<byte> privateKey)
	{
		DerivePublicKey(privateKey, _publicKey);
		privateKey.CopyTo(_privateKey);
		HasPrivateKey = true;
		HasPublicKey = true;
	}
}
