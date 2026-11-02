using CryptoBase.Hashes.Sha2;
using CryptoBase.KeyAgreements.Xdh;

namespace CryptoBase.Hpke;

/// <summary>
/// Provides DHKEM(X25519, HKDF-SHA256), the HPKE KEM 0x0020 of RFC 9180.
/// </summary>
/// <remarks>
/// <para>
/// The encapsulation key is an X25519 public key, a little-endian u-coordinate of 32 bytes, and a ciphertext, the encapsulated key, is an ephemeral public key of the same form. Every 32-byte value is a decapsulation key. It is clamped when used, and <see cref="ExportDecapsulationKey" /> writes back the bytes that were imported or derived, unclamped; a key and its clamped form import as the same key, with the same encapsulation key and shared secrets. The private seed is the input keying material of <see cref="DeriveKeyPair" />, so a key pair from <see cref="GenerateKey" /> or <see cref="ImportPrivateSeed" /> is the one that <see cref="DeriveKeyPair" /> derives from its seed, and <see cref="ExportPrivateSeed" /> writes it back unchanged.
/// </para>
/// <para>
/// A public key is accepted in any encoding, as RFC 7748 requires: the most significant bit is ignored and a u-coordinate of the field prime or more is reduced. The encoding is kept as given, and it is what the shared secret binds. A point of small order, which gives an all-zero shared secret, is rejected: <see cref="ImportEncapsulationKey" /> throws for it, and <see cref="TryDecapsulate" /> and <see cref="TryAuthDecapsulate" /> return <see langword="false" /> only for such a ciphertext or one of the wrong length. Encapsulation and decapsulation may run concurrently on one instance.
/// </para>
/// <para>
/// The shared secret binds the ciphertext and the encapsulation key, and with authentication the sender's encapsulation key too.
/// </para>
/// </remarks>
public sealed class DhKemX25519 : IHpkeAuthKem<DhKemX25519>
{
	private DhKemKey<DhKemX25519, X25519Key, Sha256Core> _key;
	private bool _disposed;

	private DhKemX25519() { }

	/// <inheritdoc />
	public static ushort KemId => 0x0020;

	/// <inheritdoc />
	public static int EncapsulationKeyLength => DhKemKey<DhKemX25519, X25519Key, Sha256Core>.EncapsulationKeyLength;

	/// <inheritdoc />
	public static int DecapsulationKeyLength => DhKemKey<DhKemX25519, X25519Key, Sha256Core>.DecapsulationKeyLength;

	/// <inheritdoc />
	public static int PrivateSeedLength => DhKemKey<DhKemX25519, X25519Key, Sha256Core>.PrivateSeedLength;

	/// <inheritdoc />
	public static int CiphertextLength => DhKemKey<DhKemX25519, X25519Key, Sha256Core>.CiphertextLength;

	/// <inheritdoc />
	public static int SharedSecretLength => DhKemKey<DhKemX25519, X25519Key, Sha256Core>.SharedSecretLength;

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
	public static DhKemX25519 GenerateKey()
	{
		DhKemX25519 kem = new();
		kem._key.GenerateKey();
		return kem;
	}

	/// <inheritdoc />
	public static DhKemX25519 DeriveKeyPair(ReadOnlySpan<byte> inputKeyMaterial)
	{
		DhKemX25519 kem = new();
		kem._key.DeriveKeyPair(inputKeyMaterial);
		return kem;
	}

	/// <inheritdoc />
	public static DhKemX25519 ImportPrivateSeed(ReadOnlySpan<byte> source)
	{
		DhKemX25519 kem = new();
		kem._key.ImportPrivateSeed(source);
		return kem;
	}

	/// <inheritdoc />
	public static DhKemX25519 ImportDecapsulationKey(ReadOnlySpan<byte> source)
	{
		DhKemX25519 kem = new();
		kem._key.ImportDecapsulationKey(source);
		return kem;
	}

	/// <inheritdoc />
	public static DhKemX25519 ImportEncapsulationKey(ReadOnlySpan<byte> source)
	{
		DhKemX25519 kem = new();
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
	public void AuthEncapsulate(DhKemX25519 sender, Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_key.AuthEncapsulate(false, default, ref KeyOf(sender), ciphertext, sharedSecret);
	}

	// For known-answer tests, as with Encapsulate.
	internal void AuthEncapsulate(ReadOnlySpan<byte> ephemeralInputKeyMaterial, DhKemX25519 sender, Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_key.AuthEncapsulate(true, ephemeralInputKeyMaterial, ref KeyOf(sender), ciphertext, sharedSecret);
	}

	/// <inheritdoc />
	public bool TryAuthDecapsulate(ReadOnlySpan<byte> ciphertext, DhKemX25519 sender, Span<byte> sharedSecret)
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

	private static ref DhKemKey<DhKemX25519, X25519Key, Sha256Core> KeyOf(DhKemX25519 sender)
	{
		ArgumentNullException.ThrowIfNull(sender);
		ObjectDisposedException.ThrowIf(sender._disposed, sender);
		return ref sender._key;
	}
}
