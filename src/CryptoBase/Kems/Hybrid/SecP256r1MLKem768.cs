using CryptoBase.EllipticCurves;
using CryptoBase.Kems.MLKem;

namespace CryptoBase.Kems.Hybrid;

/// <summary>
/// Combines elliptic curve Diffie–Hellman (ECDH) over the P-256 curve with ML-KEM-768.
/// </summary>
/// <remarks>
/// <para>
/// The encodings and the shared secret are those of the TLS group SecP256r1MLKEM768. The P-256 part comes first in every encoding and in the shared
/// secret. The encapsulation key is the public key in the uncompressed encoding followed by the ML-KEM-768 encapsulation key, a ciphertext is an
/// ephemeral public key in the same encoding followed by an ML-KEM-768 ciphertext, and the shared secret is the x-coordinate of the shared point as
/// big-endian bytes followed by the ML-KEM-768 shared secret.
/// </para>
/// <para>
/// The private seed and the decapsulation key are formats of this library. Both start with the P-256 private key as big-endian bytes, which must
/// lie in [1, n − 1], followed by the ML-KEM-768 private seed or decapsulation key.
/// </para>
/// <para>
/// A point is accepted only in the uncompressed encoding, with both coordinates below the field prime, and only if it lies on the curve.
/// <see cref="TryDecapsulate" /> returns <see langword="false" /> only for a ciphertext of the wrong length or one whose point fails this check;
/// any other ciphertext that was not encapsulated to the key is rejected implicitly by ML-KEM. Encapsulation and decapsulation may run
/// concurrently on one instance.
/// </para>
/// <para>
/// The shared secret does not bind the ciphertext: altering the ML-KEM ciphertext changes only the ML-KEM part, and negating the ephemeral public
/// key changes nothing. A protocol that relies on that binding must include the ciphertext in its key derivation or transcript.
/// </para>
/// </remarks>
public sealed class SecP256r1MLKem768 : IKem<SecP256r1MLKem768>
{
	private EcMLKemKey<P256Curve, P256Field, P256Order, MLKem768Parameters> _key;
	private bool _disposed;

	private SecP256r1MLKem768() { }

	/// <inheritdoc />
	public static int EncapsulationKeyLength => EcMLKemKey<P256Curve, P256Field, P256Order, MLKem768Parameters>.EncapsulationKeyLength;

	/// <inheritdoc />
	public static int DecapsulationKeyLength => EcMLKemKey<P256Curve, P256Field, P256Order, MLKem768Parameters>.DecapsulationKeyLength;

	/// <inheritdoc />
	public static int PrivateSeedLength => EcMLKemKey<P256Curve, P256Field, P256Order, MLKem768Parameters>.PrivateSeedLength;

	/// <inheritdoc />
	public static int CiphertextLength => EcMLKemKey<P256Curve, P256Field, P256Order, MLKem768Parameters>.CiphertextLength;

	/// <inheritdoc />
	public static int SharedSecretLength => EcMLKemKey<P256Curve, P256Field, P256Order, MLKem768Parameters>.SharedSecretLength;

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
	public static SecP256r1MLKem768 GenerateKey()
	{
		SecP256r1MLKem768 kem = new();
		kem._key.GenerateKey();
		return kem;
	}

	/// <inheritdoc />
	public static SecP256r1MLKem768 ImportPrivateSeed(ReadOnlySpan<byte> source)
	{
		SecP256r1MLKem768 kem = new();
		kem._key.ImportPrivateSeed(source);
		return kem;
	}

	/// <inheritdoc />
	public static SecP256r1MLKem768 ImportDecapsulationKey(ReadOnlySpan<byte> source)
	{
		SecP256r1MLKem768 kem = new();
		kem._key.ImportDecapsulationKey(source);
		return kem;
	}

	/// <inheritdoc />
	public static SecP256r1MLKem768 ImportEncapsulationKey(ReadOnlySpan<byte> source)
	{
		SecP256r1MLKem768 kem = new();
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
