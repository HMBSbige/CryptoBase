using CryptoBase.EllipticCurves.Curve25519;
using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.KeyAgreements.Xdh;

// The private key is any 32 bytes, kept as imported and clamped where it is used. The public key is a u-coordinate: canonical where the key derives it, the bytes as given where it was imported alone. Keep a key in one writable location and do not copy it: a copy keeps the private key where Clear cannot reach it.
internal struct X25519Key : IDiffieHellmanKey<X25519Key>
{
	internal const int PrivateKeyLength = 32;
	internal const int PublicKeyLength = 32;
	internal const int SharedSecretLength = 32;

	private InlineArray32<byte> _privateKey;
	private InlineArray32<byte> _publicKey;

	internal bool HasPrivateKey { readonly get; private set; }

	// Set whenever HasPrivateKey is.
	internal bool HasPublicKey { readonly get; private set; }

	[UnscopedRef]
	internal readonly ReadOnlySpan<byte> PublicKey
	{
		get
		{
			Debug.Assert(HasPublicKey);

			return _publicKey;
		}
	}

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

	// For a key that is used without a private key, as an encapsulation key is: false, with the key cleared, for the wrong length or a point whose shared secret is all zeros with every private key.
	internal bool TryImportPublicKey(ReadOnlySpan<byte> source)
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

	// decodeScalar25519 of RFC 7748 §5.
	internal static void Clamp(ReadOnlySpan<byte> privateKey, Span<byte> destination)
	{
		Debug.Assert(privateKey.Length is PrivateKeyLength && destination.Length is PrivateKeyLength);

		privateKey.CopyTo(destination);
		destination[0] &= 0xF8;
		destination[PrivateKeyLength - 1] = (byte)(destination[PrivateKeyLength - 1] & 0x7F | 0x40);
	}

	// X25519(k, 9) by the fixed-base multiplication on the Edwards curve and the birational map, as B maps to u = 9. The product is never the identity, which would map to 0, as a clamped k is not a multiple of L.
	[SkipLocalsInit]
	internal static void DerivePublicKey(ReadOnlySpan<byte> privateKey, Span<byte> publicKey)
	{
		Debug.Assert(publicKey.Length is PublicKeyLength);

		using CryptoBuffer<byte> scalar = new(stackalloc byte[PrivateKeyLength]);
		Clamp(privateKey, scalar.Span);
		Edwards25519.MultiplyBase(scalar.Span, out EdwardsPoint point);
		Edwards25519.ToMontgomeryU(in point, publicKey);
		point.ZeroMemory();
	}

	// X25519(k, u) into sharedSecret, unless the result is all zeros: then false, with sharedSecret unchanged. A clamped k is a multiple of 8 but not of the order of a larger subgroup of the curve or its twist, so the result is zero just for a point whose order divides 8 and the return value depends on peerPublicKey alone. The peer key is read in full before sharedSecret is written, so the two may overlap.
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
		Field25519.FromBytes(peerPublicKey, out Field25519 u);
		Curve25519KernelDispatch.Ladder(scalar.Span, in u, out Field25519 x, out Field25519 z);
		Field25519.Invert(in z, out z);
		Field25519.Multiply(in x, in z, out x);
		Field25519.ToBytes(in x, secret.Span);
		x.ZeroMemory();
		z.ZeroMemory();

		if (IsAllZeros(secret.Span))
		{
			return false;
		}

		secret.Span.CopyTo(sharedSecret);
		return true;
	}

	// X25519(k, 9) into publicKey and X25519(k, u) into sharedSecret, for a peer key that is not of small order, as an encapsulation key is not, with one inversion for both: 1/((Z − Y)·z) gives 1/(Z − Y) for the map of the fixed-base product and 1/z for the ladder. Neither factor is 0, as a clamped k is not a multiple of L or of the order of the peer point, so neither result fails.
	[SkipLocalsInit]
	internal static void DerivePublicKeyAndSharedSecret(ReadOnlySpan<byte> privateKey, ReadOnlySpan<byte> peerPublicKey, Span<byte> publicKey, Span<byte> sharedSecret)
	{
		Debug.Assert(peerPublicKey.Length is PublicKeyLength && publicKey.Length is PublicKeyLength && sharedSecret.Length is SharedSecretLength);

		using CryptoBuffer<byte> scalar = new(stackalloc byte[PrivateKeyLength]);
		Clamp(privateKey, scalar.Span);
		Edwards25519.MultiplyBase(scalar.Span, out EdwardsPoint point);
		Field25519.FromBytes(peerPublicKey, out Field25519 u);
		Curve25519KernelDispatch.Ladder(scalar.Span, in u, out Field25519 x, out Field25519 z);
		Field25519.Add(in point.Z, in point.Y, out Field25519 numerator);
		Field25519.Subtract(in point.Z, in point.Y, out Field25519 denominator);
		Field25519.Multiply(in denominator, in z, out Field25519 inverse);
		Field25519.Invert(in inverse, out inverse);
		Field25519.Multiply(in inverse, in z, out z);
		Field25519.Multiply(in inverse, in denominator, out inverse);
		Field25519.Multiply(in numerator, in z, out numerator);
		Field25519.ToBytes(in numerator, publicKey);
		Field25519.Multiply(in x, in inverse, out x);
		Field25519.ToBytes(in x, sharedSecret);
		point.ZeroMemory();
		x.ZeroMemory();
		z.ZeroMemory();
		numerator.ZeroMemory();
		denominator.ZeroMemory();
		inverse.ZeroMemory();
	}

	// Whether every shared secret with publicKey is all zeros: [8]P is the point at infinity for the point P of u-coordinate u on the curve or its twist. Three doublings on the u-line give it without a square root, (x : z) taking 2P = ((x² − z²)² : 4xz(x² + Axz + z²)), and they take constant time.
	internal static bool IsSmallOrder(ReadOnlySpan<byte> publicKey)
	{
		Debug.Assert(publicKey.Length is PublicKeyLength);

		Field25519.FromBytes(publicKey, out Field25519 x);
		Field25519 z = Field25519.One;

		for (int i = 0; i < 3; ++i)
		{
			Field25519.Add(in x, in z, out Field25519 sum);
			Field25519.Subtract(in x, in z, out Field25519 difference);
			Field25519.Square(in sum, out sum);
			Field25519.Square(in difference, out difference);
			Field25519.Subtract(in sum, in difference, out Field25519 product);
			Field25519.Multiply(in sum, in difference, out x);
			// 4xz = (x + z)² − (x − z)², and x² + Axz + z² = (x − z)² + (A + 2)/4·4xz.
			Field25519.MultiplySmall(in product, 121666, out Field25519 scaled);
			Field25519.Add(in difference, in scaled, out scaled);
			Field25519.Multiply(in product, in scaled, out z);
		}

		return Field25519.IsZero(in z) is not 0;
	}

	// The DHKEM view of the key. Every 32-byte string is a private key, exported as imported. A public key comes from TryImportPublicKey, which rejects the points of small order, or from a private key, so the shared secrets below are never all zeros.
	static int IDiffieHellmanKey<X25519Key>.PrivateKeyLength => PrivateKeyLength;

	static int IDiffieHellmanKey<X25519Key>.PublicKeyLength => PublicKeyLength;

	static int IDiffieHellmanKey<X25519Key>.SharedSecretLength => SharedSecretLength;

	static bool IDiffieHellmanKey<X25519Key>.IsEveryPrivateKeyValid => true;

	static byte IDiffieHellmanKey<X25519Key>.PrivateKeyMask => 0xFF;

	readonly bool IDiffieHellmanKey<X25519Key>.HasPrivateKey => HasPrivateKey;

	readonly bool IDiffieHellmanKey<X25519Key>.HasPublicKey => HasPublicKey;

	bool IDiffieHellmanKey<X25519Key>.TryImportPrivateKey(ReadOnlySpan<byte> source)
	{
		if (source.Length is not PrivateKeyLength)
		{
			Clear();
			return false;
		}

		SetKey(source);
		return true;
	}

	bool IDiffieHellmanKey<X25519Key>.TryImportPublicKey(ReadOnlySpan<byte> source)
	{
		return TryImportPublicKey(source);
	}

	// Unclamped, as draft-ietf-hpke-hpke serializes it; RFC 9180, Sec. 7.1.2 and its erratum 7121 clamp it instead, which gives the same key.
	readonly int IDiffieHellmanKey<X25519Key>.ExportPrivateKey(Span<byte> destination)
	{
		return ExportPrivateKey(destination);
	}

	readonly int IDiffieHellmanKey<X25519Key>.ExportPublicKey(Span<byte> destination)
	{
		return ExportPublicKey(destination);
	}

	readonly bool IDiffieHellmanKey<X25519Key>.TryDeriveSharedSecret(ReadOnlySpan<byte> peerPublicKey, Span<byte> sharedSecret)
	{
		return TryDeriveSharedSecret(peerPublicKey, sharedSecret);
	}

	static void IDiffieHellmanKey<X25519Key>.DeriveSharedSecret(in X25519Key privateKey, in X25519Key publicKey, Span<byte> destination)
	{
		Debug.Assert(privateKey.HasPrivateKey && publicKey.HasPublicKey);

		bool derived = TryDeriveSharedSecret(privateKey._privateKey, publicKey._publicKey, destination.Slice(0, SharedSecretLength));
		Debug.Assert(derived);
	}

	[SkipLocalsInit]
	static void IDiffieHellmanKey<X25519Key>.GenerateEphemeral(in X25519Key publicKey, Span<byte> ephemeralPublicKey, Span<byte> sharedSecret)
	{
		Debug.Assert(publicKey.HasPublicKey);

		using CryptoBuffer<byte> ephemeral = new(stackalloc byte[PrivateKeyLength]);
		SystemRandom.Fill(ephemeral.Span);
		DerivePublicKeyAndSharedSecret(ephemeral.Span, publicKey._publicKey, ephemeralPublicKey.Slice(0, PublicKeyLength), sharedSecret.Slice(0, SharedSecretLength));
	}

	void IDiffieHellmanKey<X25519Key>.Clear()
	{
		Clear();
	}

	// Without a branch on the contents.
	private static bool IsAllZeros(ReadOnlySpan<byte> value)
	{
		ulong bits = BinaryPrimitives.ReadUInt64LittleEndian(value) | BinaryPrimitives.ReadUInt64LittleEndian(value.Slice(8)) | BinaryPrimitives.ReadUInt64LittleEndian(value.Slice(16)) | BinaryPrimitives.ReadUInt64LittleEndian(value.Slice(24));
		return bits is 0;
	}

	private void SetKey(ReadOnlySpan<byte> privateKey)
	{
		DerivePublicKey(privateKey, _publicKey);
		privateKey.CopyTo(_privateKey);
		HasPrivateKey = true;
		HasPublicKey = true;
	}
}
