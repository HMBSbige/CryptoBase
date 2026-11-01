using CryptoBase.Kems.MLKem;

namespace CryptoBase.Kems.Hybrid;

/// <summary>
/// Combines ML-KEM-768 with X25519 (RFC 7748).
/// </summary>
/// <remarks>
/// <para>
/// The encodings and the shared secret are those of the TLS group X25519MLKEM768. Unlike in the other hybrid KEMs, the ML-KEM part comes first in every encoding and in the shared secret. The encapsulation key is the ML-KEM-768 encapsulation key followed by the X25519 public key, a ciphertext is an ML-KEM-768 ciphertext followed by an ephemeral X25519 public key, and the shared secret is the ML-KEM-768 shared secret followed by the X25519 shared secret.
/// </para>
/// <para>
/// The private seed and the decapsulation key are formats of this library: the ML-KEM-768 private seed or decapsulation key followed by the X25519 private key, any 32 bytes.
/// </para>
/// <para>
/// An X25519 public key is accepted in any encoding, as RFC 7748 requires, except a point of small order, which gives an all-zero shared secret: <see cref="ImportEncapsulationKey" /> rejects one, and <see cref="TryDecapsulate" /> returns <see langword="false" /> only for a ciphertext of the wrong length or one whose ephemeral public key is such a point; any other ciphertext that was not encapsulated to the key is rejected implicitly by ML-KEM. Encapsulation and decapsulation may run concurrently on one instance.
/// </para>
/// <para>
/// The shared secret does not bind the ciphertext: altering the ML-KEM ciphertext changes only the ML-KEM part, and setting the most significant bit of the ephemeral public key changes nothing. A protocol that relies on that binding must include the ciphertext in its key derivation or transcript.
/// </para>
/// </remarks>
public sealed class X25519MLKem768 : IKem<X25519MLKem768>
{
	private X25519MLKemKey<MLKem768Parameters> _key;
	private bool _disposed;

	private X25519MLKem768() { }

	/// <inheritdoc />
	public static int EncapsulationKeyLength => X25519MLKemKey<MLKem768Parameters>.EncapsulationKeyLength;

	/// <inheritdoc />
	public static int DecapsulationKeyLength => X25519MLKemKey<MLKem768Parameters>.DecapsulationKeyLength;

	/// <inheritdoc />
	public static int PrivateSeedLength => X25519MLKemKey<MLKem768Parameters>.PrivateSeedLength;

	/// <inheritdoc />
	public static int CiphertextLength => X25519MLKemKey<MLKem768Parameters>.CiphertextLength;

	/// <inheritdoc />
	public static int SharedSecretLength => X25519MLKemKey<MLKem768Parameters>.SharedSecretLength;

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
	public static X25519MLKem768 GenerateKey()
	{
		X25519MLKem768 kem = new();
		kem._key.GenerateKey();
		return kem;
	}

	/// <inheritdoc />
	public static X25519MLKem768 ImportPrivateSeed(ReadOnlySpan<byte> source)
	{
		X25519MLKem768 kem = new();
		kem._key.ImportPrivateSeed(source);
		return kem;
	}

	/// <inheritdoc />
	public static X25519MLKem768 ImportDecapsulationKey(ReadOnlySpan<byte> source)
	{
		X25519MLKem768 kem = new();
		kem._key.ImportDecapsulationKey(source);
		return kem;
	}

	/// <inheritdoc />
	public static X25519MLKem768 ImportEncapsulationKey(ReadOnlySpan<byte> source)
	{
		X25519MLKem768 kem = new();
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
		_key.Encapsulate(ciphertext, sharedSecret);
	}

	// For tests that rebuild the result from its parts.
	internal void Encapsulate(ReadOnlySpan<byte> ephemeralPrivateKey, ReadOnlySpan<byte> message, Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_key.Encapsulate(ephemeralPrivateKey, message, ciphertext, sharedSecret);
	}

	/// <inheritdoc />
	public bool TryDecapsulate(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _key.TryDecapsulate(ciphertext, sharedSecret);
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
}
