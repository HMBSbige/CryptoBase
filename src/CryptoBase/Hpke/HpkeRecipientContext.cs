using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Hpke;

/// <summary>
/// Provides the recipient's context of Hybrid Public Key Encryption (HPKE, RFC 9180): it decapsulates the key from one sender, then opens the sender's messages and exports secrets.
/// </summary>
/// <remarks>
/// <para>
/// <c>TryCreate</c> sets up the base or PSK mode and <c>TryCreateAuthenticated</c> the auth or auth_psk mode. They return <see langword="false" /> only if the encapsulated key fails the public checks of the KEM, such as the wrong length or a point not on the curve; an encapsulated key or other inputs that do not match the sender's give a context that opens nothing. In the PSK modes, the PSK must be at least 32 bytes long and the PSK ID must not be empty.
/// </para>
/// <para>
/// Each opened message takes the next sequence number. A recipient that sets up its context again, such as a stateless server, sets <see cref="SequenceNumber" /> to where the previous context stopped. An instance is not thread-safe. Disposal erases the keys and is idempotent; subsequent operations other than disposal throw <see cref="ObjectDisposedException" />.
/// </para>
/// </remarks>
public sealed class HpkeRecipientContext : IDisposable
{
	private HpkeContextState _state;
	private bool _disposed;

	private HpkeRecipientContext() { }

	/// <summary>
	/// Gets the KDF of the context.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public HpkeKdfId Kdf
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
	public HpkeAeadId Aead
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return _state.Aead;
		}
	}

	/// <summary>
	/// Gets or sets the sequence number of the next message.
	/// </summary>
	/// <remarks>
	/// It starts at 0 and grows by one with each message opened. Every value opens only the message that the sender sealed with it; <see cref="ulong.MaxValue" /> is the message limit.
	/// </remarks>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public ulong SequenceNumber
	{
		get
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			return _state.SequenceNumber;
		}
		set
		{
			ObjectDisposedException.ThrowIf(_disposed, this);
			_state.SequenceNumber = value;
		}
	}

	/// <summary>
	/// Sets up a context in the base mode, SetupBaseR of RFC 9180, Section 5.1.1.
	/// </summary>
	/// <typeparam name="TKem">The KEM.</typeparam>
	/// <param name="recipient">The recipient's key pair, which must hold the decapsulation key.</param>
	/// <param name="kdf">The KDF.</param>
	/// <param name="aead">The AEAD.</param>
	/// <param name="encapsulatedKey">The encapsulated key from the sender.</param>
	/// <param name="info">The application-supplied information.</param>
	/// <param name="context">The context, or <see langword="null" /> if the method returns <see langword="false" />.</param>
	/// <returns><see langword="false" /> if <paramref name="encapsulatedKey" /> fails the public checks of the KEM; otherwise, <see langword="true" />.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="recipient" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="kdf" /> or <paramref name="aead" /> is not supported.</exception>
	/// <exception cref="InvalidOperationException"><paramref name="recipient" /> does not hold the decapsulation key.</exception>
	/// <exception cref="ObjectDisposedException"><paramref name="recipient" /> has been disposed.</exception>
	public static bool TryCreate<TKem>(TKem recipient, HpkeKdfId kdf, HpkeAeadId aead, ReadOnlySpan<byte> encapsulatedKey, ReadOnlySpan<byte> info, [NotNullWhen(true)] out HpkeRecipientContext? context) where TKem : class, IHpkeKem<TKem>
	{
		ArgumentNullException.ThrowIfNull(recipient);
		HpkeContextState.ValidateSuite(kdf, aead);
		return TryDecapsulate(recipient, HpkeMode.Base, kdf, aead, encapsulatedKey, info, default, default, out context);
	}

	/// <summary>
	/// Sets up a context in the PSK mode, SetupPSKR of RFC 9180, Section 5.1.2.
	/// </summary>
	/// <typeparam name="TKem">The KEM.</typeparam>
	/// <param name="recipient">The recipient's key pair, which must hold the decapsulation key.</param>
	/// <param name="kdf">The KDF.</param>
	/// <param name="aead">The AEAD.</param>
	/// <param name="encapsulatedKey">The encapsulated key from the sender.</param>
	/// <param name="info">The application-supplied information.</param>
	/// <param name="psk">The pre-shared key, at least 32 bytes long.</param>
	/// <param name="pskId">The identifier of the pre-shared key, not empty.</param>
	/// <param name="context">The context, or <see langword="null" /> if the method returns <see langword="false" />.</param>
	/// <returns><see langword="false" /> if <paramref name="encapsulatedKey" /> fails the public checks of the KEM; otherwise, <see langword="true" />.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="recipient" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="kdf" /> or <paramref name="aead" /> is not supported.</exception>
	/// <exception cref="ArgumentException"><paramref name="psk" /> is shorter than 32 bytes, or <paramref name="pskId" /> is empty.</exception>
	/// <exception cref="InvalidOperationException"><paramref name="recipient" /> does not hold the decapsulation key.</exception>
	/// <exception cref="ObjectDisposedException"><paramref name="recipient" /> has been disposed.</exception>
	public static bool TryCreate<TKem>(TKem recipient, HpkeKdfId kdf, HpkeAeadId aead, ReadOnlySpan<byte> encapsulatedKey, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId, [NotNullWhen(true)] out HpkeRecipientContext? context) where TKem : class, IHpkeKem<TKem>
	{
		ArgumentNullException.ThrowIfNull(recipient);
		HpkeContextState.ValidateSuite(kdf, aead);
		HpkeContextState.ValidatePsk(psk, pskId);
		return TryDecapsulate(recipient, HpkeMode.Psk, kdf, aead, encapsulatedKey, info, psk, pskId, out context);
	}

	/// <summary>
	/// Sets up a context in the auth mode, SetupAuthR of RFC 9180, Section 5.1.3, for a sender authenticated with its key pair.
	/// </summary>
	/// <typeparam name="TKem">The KEM.</typeparam>
	/// <param name="recipient">The recipient's key pair, which must hold the decapsulation key.</param>
	/// <param name="sender">The sender's encapsulation key.</param>
	/// <param name="kdf">The KDF.</param>
	/// <param name="aead">The AEAD.</param>
	/// <param name="encapsulatedKey">The encapsulated key from the sender.</param>
	/// <param name="info">The application-supplied information.</param>
	/// <param name="context">The context, or <see langword="null" /> if the method returns <see langword="false" />.</param>
	/// <returns><see langword="false" /> if <paramref name="encapsulatedKey" /> fails the public checks of the KEM; otherwise, <see langword="true" />.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="recipient" /> or <paramref name="sender" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="kdf" /> or <paramref name="aead" /> is not supported.</exception>
	/// <exception cref="InvalidOperationException"><paramref name="recipient" /> does not hold the decapsulation key.</exception>
	/// <exception cref="ObjectDisposedException"><paramref name="recipient" /> or <paramref name="sender" /> has been disposed.</exception>
	public static bool TryCreateAuthenticated<TKem>(TKem recipient, TKem sender, HpkeKdfId kdf, HpkeAeadId aead, ReadOnlySpan<byte> encapsulatedKey, ReadOnlySpan<byte> info, [NotNullWhen(true)] out HpkeRecipientContext? context) where TKem : class, IHpkeAuthKem<TKem>
	{
		ArgumentNullException.ThrowIfNull(recipient);
		ArgumentNullException.ThrowIfNull(sender);
		HpkeContextState.ValidateSuite(kdf, aead);
		return TryAuthDecapsulate(recipient, sender, HpkeMode.Auth, kdf, aead, encapsulatedKey, info, default, default, out context);
	}

	/// <summary>
	/// Sets up a context in the auth_psk mode, SetupAuthPSKR of RFC 9180, Section 5.1.4, for a sender authenticated with its key pair and a pre-shared key.
	/// </summary>
	/// <typeparam name="TKem">The KEM.</typeparam>
	/// <param name="recipient">The recipient's key pair, which must hold the decapsulation key.</param>
	/// <param name="sender">The sender's encapsulation key.</param>
	/// <param name="kdf">The KDF.</param>
	/// <param name="aead">The AEAD.</param>
	/// <param name="encapsulatedKey">The encapsulated key from the sender.</param>
	/// <param name="info">The application-supplied information.</param>
	/// <param name="psk">The pre-shared key, at least 32 bytes long.</param>
	/// <param name="pskId">The identifier of the pre-shared key, not empty.</param>
	/// <param name="context">The context, or <see langword="null" /> if the method returns <see langword="false" />.</param>
	/// <returns><see langword="false" /> if <paramref name="encapsulatedKey" /> fails the public checks of the KEM; otherwise, <see langword="true" />.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="recipient" /> or <paramref name="sender" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="kdf" /> or <paramref name="aead" /> is not supported.</exception>
	/// <exception cref="ArgumentException"><paramref name="psk" /> is shorter than 32 bytes, or <paramref name="pskId" /> is empty.</exception>
	/// <exception cref="InvalidOperationException"><paramref name="recipient" /> does not hold the decapsulation key.</exception>
	/// <exception cref="ObjectDisposedException"><paramref name="recipient" /> or <paramref name="sender" /> has been disposed.</exception>
	public static bool TryCreateAuthenticated<TKem>(TKem recipient, TKem sender, HpkeKdfId kdf, HpkeAeadId aead, ReadOnlySpan<byte> encapsulatedKey, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId, [NotNullWhen(true)] out HpkeRecipientContext? context) where TKem : class, IHpkeAuthKem<TKem>
	{
		ArgumentNullException.ThrowIfNull(recipient);
		ArgumentNullException.ThrowIfNull(sender);
		HpkeContextState.ValidateSuite(kdf, aead);
		HpkeContextState.ValidatePsk(psk, pskId);
		return TryAuthDecapsulate(recipient, sender, HpkeMode.AuthPsk, kdf, aead, encapsulatedKey, info, psk, pskId, out context);
	}

	// The key schedule of a shared secret that the KEM of kemId decapsulated; known-answer tests start here.
	internal static HpkeRecipientContext Create(ushort kemId, HpkeMode mode, HpkeKdfId kdf, HpkeAeadId aead, ReadOnlySpan<byte> sharedSecret, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId)
	{
		HpkeRecipientContext context = new();
		context._state.Initialize(kemId, mode, kdf, aead, sharedSecret, info, psk, pskId);
		return context;
	}

	/// <summary>
	/// Authenticates and decrypts a message, ContextR.Open of RFC 9180, Section 5.2.
	/// </summary>
	/// <remarks>
	/// <para>
	/// <paramref name="ciphertext" /> and <paramref name="plaintext" /> may start at the same byte, to open in place; otherwise they must not overlap.
	/// </para>
	/// <para>
	/// The method returns <see langword="false" /> if <paramref name="ciphertext" /> is shorter than the tag or fails authentication, as it does with the wrong sequence number, associated data or key. The sequence number then remains unchanged, and the part of <paramref name="plaintext" /> that would have received the message is cleared.
	/// </para>
	/// </remarks>
	/// <param name="ciphertext">The ciphertext, which ends with the tag.</param>
	/// <param name="plaintext">The buffer that receives the message, which is shorter than the ciphertext by the tag size of the AEAD, <c>Aead.TagSize</c>.</param>
	/// <param name="associatedData">The associated data that the message was sealed with.</param>
	/// <returns><see langword="true" /> if the message was opened; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="plaintext" /> is too short or overlaps <paramref name="ciphertext" /> without starting at the same byte.</exception>
	/// <exception cref="InvalidOperationException">The AEAD of the context is <see cref="HpkeAeadId.ExportOnly" />.</exception>
	/// <exception cref="CryptographicException">The sequence number has reached its limit, <see cref="ulong.MaxValue" />.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public bool TryOpen(ReadOnlySpan<byte> ciphertext, Span<byte> plaintext, ReadOnlySpan<byte> associatedData = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _state.TryOpen(ciphertext, plaintext, associatedData);
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
	private static bool TryDecapsulate<TKem>(TKem recipient, HpkeMode mode, HpkeKdfId kdf, HpkeAeadId aead, ReadOnlySpan<byte> encapsulatedKey, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId, [NotNullWhen(true)] out HpkeRecipientContext? context) where TKem : class, IHpkeKem<TKem>
	{
		int length = TKem.SharedSecretLength;
		using CryptoBuffer<byte> sharedSecret = CryptoBuffer<byte>.ShouldUsePool(length) ? new CryptoBuffer<byte>(length) : new CryptoBuffer<byte>(stackalloc byte[length]);
		context = recipient.TryDecapsulate(encapsulatedKey, sharedSecret.Span) ? Create(TKem.KemId, mode, kdf, aead, sharedSecret.Span, info, psk, pskId) : null;
		return context is not null;
	}

	[SkipLocalsInit]
	private static bool TryAuthDecapsulate<TKem>(TKem recipient, TKem sender, HpkeMode mode, HpkeKdfId kdf, HpkeAeadId aead, ReadOnlySpan<byte> encapsulatedKey, ReadOnlySpan<byte> info, ReadOnlySpan<byte> psk, ReadOnlySpan<byte> pskId, [NotNullWhen(true)] out HpkeRecipientContext? context) where TKem : class, IHpkeAuthKem<TKem>
	{
		int length = TKem.SharedSecretLength;
		using CryptoBuffer<byte> sharedSecret = CryptoBuffer<byte>.ShouldUsePool(length) ? new CryptoBuffer<byte>(length) : new CryptoBuffer<byte>(stackalloc byte[length]);
		context = recipient.TryAuthDecapsulate(encapsulatedKey, sender, sharedSecret.Span) ? Create(TKem.KemId, mode, kdf, aead, sharedSecret.Span, info, psk, pskId) : null;
		return context is not null;
	}
}
