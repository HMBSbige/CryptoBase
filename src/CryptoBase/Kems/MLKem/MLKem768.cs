namespace CryptoBase.Kems.MLKem;

/// <summary>
/// Provides ML-KEM-768, the module-lattice-based key-encapsulation mechanism of FIPS 203 with the parameter set for security category 3.
/// </summary>
/// <remarks>
/// <para>
/// Importing an encapsulation key performs the modulus check of FIPS 203, Section 7.2. Importing a decapsulation key performs the checks of Section 7.3
/// and the modulus check on both the embedded encapsulation key and the secret vector.
/// </para>
/// <para>
/// The private seed is d ‖ z, 64 bytes. The key is expanded once, when it is generated or imported. Encapsulation and decapsulation may run concurrently
/// on one instance.
/// </para>
/// </remarks>
public sealed class MLKem768 : IKem<MLKem768>
{
	private MLKemKey<MLKem768Parameters> _key;
	private bool _disposed;

	private MLKem768() { }

	/// <inheritdoc />
	public static int EncapsulationKeyLength => MLKemKey<MLKem768Parameters>.EncapsulationKeyLength;

	/// <inheritdoc />
	public static int DecapsulationKeyLength => MLKemKey<MLKem768Parameters>.DecapsulationKeyLength;

	/// <inheritdoc />
	public static int PrivateSeedLength => MLKemKey<MLKem768Parameters>.PrivateSeedLength;

	/// <inheritdoc />
	public static int CiphertextLength => MLKemKey<MLKem768Parameters>.CiphertextLength;

	/// <inheritdoc />
	public static int SharedSecretLength => MLKemKey<MLKem768Parameters>.SharedSecretLength;

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
	public static MLKem768 GenerateKey()
	{
		MLKem768 kem = new();
		kem._key.GenerateKey();
		return kem;
	}

	/// <inheritdoc />
	public static MLKem768 ImportPrivateSeed(ReadOnlySpan<byte> source)
	{
		MLKem768 kem = new();
		kem._key.ImportPrivateSeed(source);
		return kem;
	}

	/// <inheritdoc />
	public static MLKem768 ImportDecapsulationKey(ReadOnlySpan<byte> source)
	{
		MLKem768 kem = new();
		kem._key.ImportDecapsulationKey(source);
		return kem;
	}

	/// <inheritdoc />
	public static MLKem768 ImportEncapsulationKey(ReadOnlySpan<byte> source)
	{
		MLKem768 kem = new();
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

	// ML-KEM.Encaps_internal with a given m, for known-answer tests.
	internal void Encapsulate(ReadOnlySpan<byte> message, Span<byte> ciphertext, Span<byte> sharedSecret)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_key.Encapsulate(message, ciphertext, sharedSecret);
	}

	/// <inheritdoc />
	public void Decapsulate(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_key.Decapsulate(ciphertext, sharedSecret);
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
