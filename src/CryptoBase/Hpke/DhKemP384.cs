using CryptoBase.EllipticCurves;
using CryptoBase.Hashes.Sha2;
using CryptoBase.KeyAgreements.Ecdh;

namespace CryptoBase.Hpke;

/// <summary>
/// Provides DHKEM(P-384, HKDF-SHA384), the HPKE KEM 0x0011 of RFC 9180.
/// </summary>
/// <remarks>
/// <para>
/// The encapsulation key is the public key in the uncompressed encoding, and a ciphertext, the encapsulated key, is an ephemeral public key in the same encoding. The decapsulation key is the private key as big-endian bytes, which must lie in [1, n − 1]. The private seed is the input keying material of <see cref="DeriveKeyPair" />, so a key pair from <see cref="GenerateKey" /> or <see cref="ImportPrivateSeed" /> is the one that <see cref="DeriveKeyPair" /> derives from its seed.
/// </para>
/// <para>
/// A point is accepted only in the uncompressed encoding, with both coordinates below the field prime, and only if it lies on the curve. <see cref="TryDecapsulate" /> and <see cref="TryAuthDecapsulate" /> return <see langword="false" /> only for a ciphertext of the wrong length or one whose point fails this check. Encapsulation and decapsulation may run concurrently on one instance.
/// </para>
/// <para>
/// The shared secret binds the ciphertext and the encapsulation key, and with authentication the sender's encapsulation key too.
/// </para>
/// </remarks>
public sealed class DhKemP384 : IHpkeAuthKem<DhKemP384>
{
	private DhKemKey<DhKemP384, EcdhKey<P384Curve, P384CurveField, P384Order>, Sha384Core> _key;
	private bool _disposed;

	private DhKemP384() { }

	/// <inheritdoc />
	public static ushort KemId => 0x0011;

	/// <inheritdoc />
	public static int EncapsulationKeyLength => DhKemKey<DhKemP384, EcdhKey<P384Curve, P384CurveField, P384Order>, Sha384Core>.EncapsulationKeyLength;

	/// <inheritdoc />
	public static int DecapsulationKeyLength => DhKemKey<DhKemP384, EcdhKey<P384Curve, P384CurveField, P384Order>, Sha384Core>.DecapsulationKeyLength;

	/// <inheritdoc />
	public static int PrivateSeedLength => DhKemKey<DhKemP384, EcdhKey<P384Curve, P384CurveField, P384Order>, Sha384Core>.PrivateSeedLength;

	/// <inheritdoc />
	public static int CiphertextLength => DhKemKey<DhKemP384, EcdhKey<P384Curve, P384CurveField, P384Order>, Sha384Core>.CiphertextLength;

	/// <inheritdoc />
	public static int SharedSecretLength => DhKemKey<DhKemP384, EcdhKey<P384Curve, P384CurveField, P384Order>, Sha384Core>.SharedSecretLength;

	/// <inheritdoc />
	public bool HasPrivateSeed
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return _key.HasPrivateSeed;
		}
	}

	/// <inheritdoc />
	public bool HasDecapsulationKey
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return _key.HasDecapsulationKey;
		}
	}

	/// <inheritdoc />
	public static DhKemP384 GenerateKey()
	{
		DhKemP384 kem = new();
		kem._key.GenerateKey();
		return kem;
	}

	/// <inheritdoc />
	public static DhKemP384 DeriveKeyPair(ReadOnlySpan<byte> inputKeyMaterial)
	{
		DhKemP384 kem = new();
		kem._key.DeriveKeyPair(inputKeyMaterial);
		return kem;
	}

	/// <inheritdoc />
	public static DhKemP384 ImportPrivateSeed(ReadOnlySpan<byte> source)
	{
		DhKemP384 kem = new();
		kem._key.ImportPrivateSeed(source);
		return kem;
	}

	/// <inheritdoc />
	public static DhKemP384 ImportDecapsulationKey(ReadOnlySpan<byte> source)
	{
		DhKemP384 kem = new();
		kem._key.ImportDecapsulationKey(source);
		return kem;
	}

	/// <inheritdoc />
	public static DhKemP384 ImportEncapsulationKey(ReadOnlySpan<byte> source)
	{
		DhKemP384 kem = new();
		kem._key.ImportEncapsulationKey(source);
		return kem;
	}

	/// <inheritdoc />
	public int ExportPrivateSeed(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.ExportPrivateSeed(destination);
	}

	/// <inheritdoc />
	public int ExportDecapsulationKey(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.ExportDecapsulationKey(destination);
	}

	/// <inheritdoc />
	public int ExportEncapsulationKey(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.ExportEncapsulationKey(destination);
	}

	/// <inheritdoc />
	public void Encapsulate(Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_key.Encapsulate(false, default, ciphertext, sharedSecret);
	}

	// For known-answer tests: the ephemeral key pair is DeriveKeyPair(ephemeralInputKeyMaterial).
	internal void Encapsulate(ReadOnlySpan<byte> ephemeralInputKeyMaterial, Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_key.Encapsulate(true, ephemeralInputKeyMaterial, ciphertext, sharedSecret);
	}

	/// <inheritdoc />
	public bool TryDecapsulate(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.TryDecapsulate(ciphertext, sharedSecret);
	}

	/// <inheritdoc />
	public void AuthEncapsulate(DhKemP384 sender, Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_key.AuthEncapsulate(false, default, ref KeyOf(sender), ciphertext, sharedSecret);
	}

	// For known-answer tests, as with Encapsulate.
	internal void AuthEncapsulate(ReadOnlySpan<byte> ephemeralInputKeyMaterial, DhKemP384 sender, Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_key.AuthEncapsulate(true, ephemeralInputKeyMaterial, ref KeyOf(sender), ciphertext, sharedSecret);
	}

	/// <inheritdoc />
	public bool TryAuthDecapsulate(ReadOnlySpan<byte> ciphertext, DhKemP384 sender, Span<byte> sharedSecret)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.TryAuthDecapsulate(ciphertext, ref KeyOf(sender), sharedSecret);
	}

	/// <inheritdoc />
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_key.Clear();
		_disposed = true;
	}

	private static ref DhKemKey<DhKemP384, EcdhKey<P384Curve, P384CurveField, P384Order>, Sha384Core> KeyOf(DhKemP384 sender)
	{
		ArgumentNullException.ThrowIfNull(sender);
		ObjectDisposedException.ThrowIf(sender._disposed, sender);
		return ref sender._key;
	}
}
