namespace CryptoBase.Hpke;

/// <summary>
/// Provides the sender's context of Hybrid Public Key Encryption (HPKE, RFC 9180): it encapsulates a key to one recipient, then seals messages to the recipient and exports secrets.
/// </summary>
/// <remarks>
/// <para>
/// <c>Create</c> sets up the base or PSK mode and <c>CreateAuthenticated</c> the auth or auth_psk mode, writing the encapsulated key, enc, which the recipient needs. The encapsulated key is <c>TKem.CiphertextLength</c> bytes long, and a longer buffer receives it at its start. In the PSK modes, the PSK must be at least 32 bytes long and the PSK ID must not be empty.
/// </para>
/// <para>
/// Each sealed message takes the next sequence number, so the recipient must open the messages in the order they were sealed. An instance is not thread-safe. Disposal erases the keys and is idempotent; subsequent operations other than disposal throw <see cref="ObjectDisposedException" />.
/// </para>
/// </remarks>
public sealed class HpkeSenderContext : IDisposable
{
	private HpkeContextState _state;
	private bool _disposed;

	private HpkeSenderContext() { }

	/// <summary>
	/// Gets the KDF of the context.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public HpkeKdf Kdf
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return _state.Kdf;
		}
	}

	/// <summary>
	/// Gets the AEAD of the context.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public HpkeAead Aead
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return _state.Aead;
		}
	}

	/// <summary>
	/// Gets the sequence number of the next message, the number of messages sealed so far.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public ulong SequenceNumber
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return _state.SequenceNumber;
		}
	}

	/// <summary>
	/// Sets up a context in the base mode, SetupBaseS of RFC 9180, Section 5.1.1.
	/// </summary>
	/// <typeparam name="TKem">The KEM.</typeparam>
	/// <param name="recipient">The recipient's encapsulation key.</param>
	/// <param name="kdf">The KDF.</param>
	/// <param name="aead">The AEAD.</param>
	/// <param name="encapsulatedKey">The buffer that receives the encapsulated key. It must not overlap the other inputs.</param>
	/// <param name="info">The application-supplied information.</param>
	/// <returns>The context.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="recipient" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="kdf" /> or <paramref name="aead" /> is not supported.</exception>
	/// <exception cref="ArgumentException"><paramref name="encapsulatedKey" /> is too short or overlaps another input.</exception>
	/// <exception cref="ObjectDisposedException"><paramref name="recipient" /> has been disposed.</exception>
	public static HpkeSenderContext Create<TKem>(TKem recipient, HpkeKdf kdf, HpkeAead aead, Span<byte> encapsulatedKey, ReadOnlySpan<byte> info = default) where TKem : class, IHpkeKem<TKem>
	{
		ArgumentNullException.ThrowIfNull(recipient);
		HpkeContextState.ValidateSuite(kdf, aead);
		return Encapsulate(recipient, HpkeMode.Base, kdf, aead, encapsulatedKey, info, default, default);
	}

	/// <summary>
	/// Sets up a context in the PSK mode, SetupPSKS of RFC 9180, Section 5.1.2.
	/// </summary>
	/// <typeparam name="TKem">The KEM.</typeparam>
	/// <param name="recipient">The recipient's encapsulation key.</param>
	/// <param name="kdf">The KDF.</param>
	/// <param name="aead">The AEAD.</param>
	/// <param name="encapsulatedKey">The buffer that receives the encapsulated key. It must not overlap the other inputs.</param>
	/// <param name="info">The application-supplied information.</param>
	/// <param name="psk">The pre-shared key, at least 32 bytes long.</param>
	/// <param name="pskId">The identifier of the pre-shared key, not empty.</param>
	/// <returns>The context.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="recipient" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="kdf" /> or <paramref name="aead" /> is not supported.</exception>
	/// <exception cref="ArgumentException">
	/// <paramref name="psk" /> is shorter than 32 bytes, <paramref name="pskId" /> is empty, or <paramref name="encapsulatedKey" /> is too short or overlaps another input.
	/// </exception>
	/// <exception cref="ObjectDisposedException"><paramref name="recipient" /> has been disposed.</exception>
	public static HpkeSenderContext Create<TKem>(TKem recipient, HpkeKdf kdf, HpkeAead aead, Span<byte> encapsulatedKey, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId) where TKem : class, IHpkeKem<TKem>
	{
		ArgumentNullException.ThrowIfNull(recipient);
		HpkeContextState.ValidateSuite(kdf, aead);
		HpkeContextState.ValidatePsk(psk, pskId);
		return Encapsulate(recipient, HpkeMode.Psk, kdf, aead, encapsulatedKey, info, psk, pskId);
	}

	/// <summary>
	/// Sets up a context in the auth mode, SetupAuthS of RFC 9180, Section 5.1.3, which authenticates the sender with its key pair.
	/// </summary>
	/// <typeparam name="TKem">The KEM.</typeparam>
	/// <param name="recipient">The recipient's encapsulation key.</param>
	/// <param name="sender">The sender's key pair, which must hold the decapsulation key.</param>
	/// <param name="kdf">The KDF.</param>
	/// <param name="aead">The AEAD.</param>
	/// <param name="encapsulatedKey">The buffer that receives the encapsulated key. It must not overlap the other inputs.</param>
	/// <param name="info">The application-supplied information.</param>
	/// <returns>The context.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="recipient" /> or <paramref name="sender" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="kdf" /> or <paramref name="aead" /> is not supported.</exception>
	/// <exception cref="ArgumentException">
	/// <paramref name="sender" /> does not hold the decapsulation key, or <paramref name="encapsulatedKey" /> is too short or overlaps another input.
	/// </exception>
	/// <exception cref="ObjectDisposedException"><paramref name="recipient" /> or <paramref name="sender" /> has been disposed.</exception>
	public static HpkeSenderContext CreateAuthenticated<TKem>(TKem recipient, TKem sender, HpkeKdf kdf, HpkeAead aead, Span<byte> encapsulatedKey, ReadOnlySpan<byte> info = default) where TKem : class, IHpkeAuthKem<TKem>
	{
		ArgumentNullException.ThrowIfNull(recipient);
		ArgumentNullException.ThrowIfNull(sender);
		HpkeContextState.ValidateSuite(kdf, aead);
		return AuthEncapsulate(recipient, sender, HpkeMode.Auth, kdf, aead, encapsulatedKey, info, default, default);
	}

	/// <summary>
	/// Sets up a context in the auth_psk mode, SetupAuthPSKS of RFC 9180, Section 5.1.4, which authenticates the sender with its key pair and a pre-shared key.
	/// </summary>
	/// <typeparam name="TKem">The KEM.</typeparam>
	/// <param name="recipient">The recipient's encapsulation key.</param>
	/// <param name="sender">The sender's key pair, which must hold the decapsulation key.</param>
	/// <param name="kdf">The KDF.</param>
	/// <param name="aead">The AEAD.</param>
	/// <param name="encapsulatedKey">The buffer that receives the encapsulated key. It must not overlap the other inputs.</param>
	/// <param name="info">The application-supplied information.</param>
	/// <param name="psk">The pre-shared key, at least 32 bytes long.</param>
	/// <param name="pskId">The identifier of the pre-shared key, not empty.</param>
	/// <returns>The context.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="recipient" /> or <paramref name="sender" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="kdf" /> or <paramref name="aead" /> is not supported.</exception>
	/// <exception cref="ArgumentException">
	/// <paramref name="sender" /> does not hold the decapsulation key, <paramref name="psk" /> is shorter than 32 bytes, <paramref name="pskId" /> is empty, or <paramref name="encapsulatedKey" /> is too short or overlaps another input.
	/// </exception>
	/// <exception cref="ObjectDisposedException"><paramref name="recipient" /> or <paramref name="sender" /> has been disposed.</exception>
	public static HpkeSenderContext CreateAuthenticated<TKem>(TKem recipient, TKem sender, HpkeKdf kdf, HpkeAead aead, Span<byte> encapsulatedKey, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId) where TKem : class, IHpkeAuthKem<TKem>
	{
		ArgumentNullException.ThrowIfNull(recipient);
		ArgumentNullException.ThrowIfNull(sender);
		HpkeContextState.ValidateSuite(kdf, aead);
		HpkeContextState.ValidatePsk(psk, pskId);
		return AuthEncapsulate(recipient, sender, HpkeMode.AuthPsk, kdf, aead, encapsulatedKey, info, psk, pskId);
	}

	// The key schedule of a shared secret that the KEM of kemId encapsulated; known-answer tests start here.
	internal static HpkeSenderContext Create(ushort kemId, HpkeMode mode, HpkeKdf kdf, HpkeAead aead, ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId)
	{
		HpkeSenderContext context = new();
		context._state.Initialize(kemId, mode, kdf, aead, sharedSecret, info, psk, pskId);
		return context;
	}

	/// <summary>
	/// Encrypts and authenticates a message, ContextS.Seal of RFC 9180, Section 5.2.
	/// </summary>
	/// <remarks>
	/// <paramref name="plaintext" /> and <paramref name="ciphertext" /> may start at the same byte, to seal in place; otherwise they must not overlap. On failure, the sequence number remains unchanged.
	/// </remarks>
	/// <param name="plaintext">The message.</param>
	/// <param name="ciphertext">The buffer that receives the ciphertext, which is longer than the plaintext by the tag size of the AEAD, <c>Aead.TagSize</c>.</param>
	/// <param name="associatedData">The associated data.</param>
	/// <returns>The length of the ciphertext.</returns>
	/// <exception cref="ArgumentException"><paramref name="ciphertext" /> is too short or overlaps <paramref name="plaintext" /> without starting at the same byte.</exception>
	/// <exception cref="InvalidOperationException">The AEAD of the context is <see cref="HpkeAead.ExportOnly" />.</exception>
	/// <exception cref="CryptographicException">The sequence number has reached its limit, <see cref="ulong.MaxValue" />.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int Seal(ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, ReadOnlySpan<byte> associatedData = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _state.Seal(plaintext, ciphertext, associatedData);
	}

	/// <summary>
	/// Derives a secret from the context, Context.Export of RFC 9180, Section 5.3.
	/// </summary>
	/// <remarks><paramref name="exporterContext" /> may overlap <paramref name="destination" />.</remarks>
	/// <param name="exporterContext">The exporter context.</param>
	/// <param name="destination">The buffer that receives the secret. Its length, at most 255 times the hash length of the KDF, <c>Kdf.HashLength</c>, selects how many bytes are derived.</param>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="destination" /> is too long.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public void Export(ReadOnlySpan<byte> exporterContext, Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_state.Export(exporterContext, destination);
	}

	/// <inheritdoc />
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_state.Clear();
		_disposed = true;
	}

	[SkipLocalsInit]
	private static HpkeSenderContext Encapsulate<TKem>(TKem recipient, HpkeMode mode, HpkeKdf kdf, HpkeAead aead, Span<byte> encapsulatedKey, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId) where TKem : class, IHpkeKem<TKem>
	{
		encapsulatedKey = SliceEncapsulatedKey(encapsulatedKey, TKem.CiphertextLength, info, psk, pskId);
		int length = TKem.SharedSecretLength;
		using CryptoBuffer<byte> sharedSecret = CryptoBuffer<byte>.ShouldUsePool(length) ? new CryptoBuffer<byte>(length) : new CryptoBuffer<byte>(stackalloc byte[length]);
		recipient.Encapsulate(encapsulatedKey, sharedSecret.Span);
		return Create(TKem.KemId, mode, kdf, aead, sharedSecret.Span, info, psk, pskId);
	}

	[SkipLocalsInit]
	private static HpkeSenderContext AuthEncapsulate<TKem>(TKem recipient, TKem sender, HpkeMode mode, HpkeKdf kdf, HpkeAead aead, Span<byte> encapsulatedKey, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId) where TKem : class, IHpkeAuthKem<TKem>
	{
		encapsulatedKey = SliceEncapsulatedKey(encapsulatedKey, TKem.CiphertextLength, info, psk, pskId);
		int length = TKem.SharedSecretLength;
		using CryptoBuffer<byte> sharedSecret = CryptoBuffer<byte>.ShouldUsePool(length) ? new CryptoBuffer<byte>(length) : new CryptoBuffer<byte>(stackalloc byte[length]);
		recipient.AuthEncapsulate(sender, encapsulatedKey, sharedSecret.Span);
		return Create(TKem.KemId, mode, kdf, aead, sharedSecret.Span, info, psk, pskId);
	}

	// enc is written before the key schedule reads the other inputs, so it must not overlap them.
	private static Span<byte> SliceEncapsulatedKey(Span<byte> encapsulatedKey, int length, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(encapsulatedKey.Length, length, nameof(encapsulatedKey));
		encapsulatedKey = encapsulatedKey.Slice(0, length);

		if (ByteSpans.Overlaps(encapsulatedKey, info) || ByteSpans.Overlaps(encapsulatedKey, psk) || ByteSpans.Overlaps(encapsulatedKey, pskId))
		{
			ThrowHelper.ThrowInputOutputOverlap(nameof(encapsulatedKey));
		}

		return encapsulatedKey;
	}
}
