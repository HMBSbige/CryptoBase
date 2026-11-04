using CryptoBase.Hashes.Sha2;
using CryptoBase.KeyAgreements.Xdh;

namespace CryptoBase.Hpke;

/// <summary>
/// Provides DHKEM(X448, HKDF-SHA512), the HPKE KEM 0x0021 of RFC 9180.
/// </summary>
/// <remarks>
/// <para>
/// The encapsulation key is an X448 public key, a little-endian u-coordinate of 56 bytes, and a ciphertext, the encapsulated key, is an ephemeral public key of the same form. Every 56-byte value is a decapsulation key except those whose clamped value is 4L, four times the order of the base point, whose encapsulation key is all zeros: <see cref="ImportDecapsulationKey" /> throws for one, <see cref="DeriveKeyPair" /> and <see cref="ImportPrivateSeed" /> throw if they derive one (probability 2^−445), and <see cref="GenerateKey" /> draws another seed. A decapsulation key is clamped when used, and <see cref="ExportDecapsulationKey" /> writes back the bytes that were imported or derived, unclamped; a key and its clamped form import as the same key, with the same encapsulation key and shared secrets. The private seed is the input keying material of <see cref="DeriveKeyPair" />, so a key pair from <see cref="GenerateKey" /> or <see cref="ImportPrivateSeed" /> is the one that <see cref="DeriveKeyPair" /> derives from its seed, and <see cref="ExportPrivateSeed" /> writes it back unchanged.
/// </para>
/// <para>
/// A public key is accepted in any encoding, as RFC 7748 requires: no bit is ignored, and a u-coordinate of the field prime or more is reduced. The encoding is kept as given, and it is what the shared secret binds. A point of small order, which gives an all-zero shared secret, is rejected: <see cref="ImportEncapsulationKey" /> throws for it, and <see cref="TryDecapsulate" /> and <see cref="TryAuthDecapsulate" /> return <see langword="false" /> only for such a ciphertext or one of the wrong length. Encapsulation and decapsulation may run concurrently on one instance.
/// </para>
/// <para>
/// The shared secret binds the ciphertext and the encapsulation key, and with authentication the sender's encapsulation key too.
/// </para>
/// </remarks>
public sealed class DhKemX448 : IHpkeAuthKem<DhKemX448>
{
	private DhKemKey<DhKemX448, X448Key, Sha512Core> _key;
	private bool _disposed;

	private DhKemX448() { }

	/// <inheritdoc />
	public static ushort KemId => 0x0021;

	/// <inheritdoc />
	public static int EncapsulationKeyLength => DhKemKey<DhKemX448, X448Key, Sha512Core>.EncapsulationKeyLength;

	/// <inheritdoc />
	public static int DecapsulationKeyLength => DhKemKey<DhKemX448, X448Key, Sha512Core>.DecapsulationKeyLength;

	/// <inheritdoc />
	public static int PrivateSeedLength => DhKemKey<DhKemX448, X448Key, Sha512Core>.PrivateSeedLength;

	/// <inheritdoc />
	public static int CiphertextLength => DhKemKey<DhKemX448, X448Key, Sha512Core>.CiphertextLength;

	/// <inheritdoc />
	public static int SharedSecretLength => DhKemKey<DhKemX448, X448Key, Sha512Core>.SharedSecretLength;

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
	public static DhKemX448 GenerateKey()
	{
		DhKemX448 kem = new();
		kem._key.GenerateKey();
		return kem;
	}

	/// <inheritdoc />
	public static DhKemX448 DeriveKeyPair(ReadOnlySpan<byte> inputKeyMaterial)
	{
		DhKemX448 kem = new();
		kem._key.DeriveKeyPair(inputKeyMaterial);
		return kem;
	}

	/// <inheritdoc />
	public static DhKemX448 ImportPrivateSeed(ReadOnlySpan<byte> source)
	{
		DhKemX448 kem = new();
		kem._key.ImportPrivateSeed(source);
		return kem;
	}

	/// <inheritdoc />
	public static DhKemX448 ImportDecapsulationKey(ReadOnlySpan<byte> source)
	{
		DhKemX448 kem = new();
		kem._key.ImportDecapsulationKey(source);
		return kem;
	}

	/// <inheritdoc />
	public static DhKemX448 ImportEncapsulationKey(ReadOnlySpan<byte> source)
	{
		DhKemX448 kem = new();
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
	public void AuthEncapsulate(DhKemX448 sender, Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_key.AuthEncapsulate(false, default, ref KeyOf(sender), ciphertext, sharedSecret);
	}

	// For known-answer tests, as with Encapsulate.
	internal void AuthEncapsulate(ReadOnlySpan<byte> ephemeralInputKeyMaterial, DhKemX448 sender, Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_key.AuthEncapsulate(true, ephemeralInputKeyMaterial, ref KeyOf(sender), ciphertext, sharedSecret);
	}

	/// <inheritdoc />
	public bool TryAuthDecapsulate(ReadOnlySpan<byte> ciphertext, DhKemX448 sender, Span<byte> sharedSecret)
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

	private static ref DhKemKey<DhKemX448, X448Key, Sha512Core> KeyOf(DhKemX448 sender)
	{
		ArgumentNullException.ThrowIfNull(sender);
		ObjectDisposedException.ThrowIf(sender._disposed, sender);
		return ref sender._key;
	}
}
