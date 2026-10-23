namespace CryptoBase.Kems.MLKem;

/// <summary>
/// Provides ML-KEM-1024, the module-lattice-based key-encapsulation mechanism of FIPS 203 with the parameter set for security category 5.
/// </summary>
/// <remarks>
/// <para>
/// Importing an encapsulation key performs the modulus check of FIPS 203, Section 7.2. Importing a decapsulation key performs the checks of Section 7.3
/// and the modulus check on both the embedded encapsulation key and the secret vector.
/// </para>
/// <para>
/// <see cref="TryDecapsulate" /> returns <see langword="false" /> only for a ciphertext of the wrong length; any other ciphertext that was not
/// encapsulated to the key is rejected implicitly.
/// </para>
/// <para>
/// The private seed is d ‖ z, and every 64-byte value is valid. The key is expanded once, when it is generated or imported. Encapsulation and
/// decapsulation may run concurrently on one instance.
/// </para>
/// </remarks>
public sealed class MLKem1024 : IKem<MLKem1024>
{
	private MLKemKey<MLKem1024Parameters> _key;
	private bool _disposed;

	private MLKem1024() { }

	/// <inheritdoc />
	public static int EncapsulationKeyLength => MLKemKey<MLKem1024Parameters>.EncapsulationKeyLength;

	/// <inheritdoc />
	public static int DecapsulationKeyLength => MLKemKey<MLKem1024Parameters>.DecapsulationKeyLength;

	/// <inheritdoc />
	public static int PrivateSeedLength => MLKemKey<MLKem1024Parameters>.PrivateSeedLength;

	/// <inheritdoc />
	public static int CiphertextLength => MLKemKey<MLKem1024Parameters>.CiphertextLength;

	/// <inheritdoc />
	public static int SharedSecretLength => MLKemKey<MLKem1024Parameters>.SharedSecretLength;

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
	public static MLKem1024 GenerateKey()
	{
		MLKem1024 kem = new();
		kem._key.GenerateKey();
		return kem;
	}

	/// <inheritdoc />
	public static MLKem1024 ImportPrivateSeed(ReadOnlySpan<byte> source)
	{
		MLKem1024 kem = new();
		kem._key.ImportPrivateSeed(source);
		return kem;
	}

	/// <inheritdoc />
	public static MLKem1024 ImportDecapsulationKey(ReadOnlySpan<byte> source)
	{
		MLKem1024 kem = new();
		kem._key.ImportDecapsulationKey(source);
		return kem;
	}

	/// <inheritdoc />
	public static MLKem1024 ImportEncapsulationKey(ReadOnlySpan<byte> source)
	{
		MLKem1024 kem = new();
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
