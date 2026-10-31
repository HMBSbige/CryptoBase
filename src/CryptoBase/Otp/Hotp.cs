namespace CryptoBase.Otp;

/// <summary>
/// Generates and verifies HMAC-based one-time passwords (HOTP), as specified by RFC 4226.
/// </summary>
/// <remarks>
/// <para>
/// For HMACs longer than 20 bytes, dynamic truncation takes its offset from the last HMAC byte, as RFC 6238 does.
/// </para>
/// <para>
/// <see cref="Generate" /> and <see cref="Verify" /> do not change the instance, so they may be called concurrently.
/// </para>
/// </remarks>
/// <typeparam name="TCore">
/// The hash core of the HMAC, such as <c>Sha1Core</c>, the hash of RFC 4226. Its output must be at least 20 bytes long.
/// </typeparam>
public sealed class Hotp<TCore> : IDisposable where TCore : unmanaged, IHmacHashCore<TCore>
{
	private OtpKey<TCore> _key;
	private bool _disposed;

	private Hotp(OtpCodeFormat format)
	{
		Format = format;
	}

	/// <summary>
	/// Gets the code format.
	/// </summary>
	public OtpCodeFormat Format { get; }

	/// <summary>
	/// Creates an instance that holds a key.
	/// </summary>
	/// <param name="key">The shared secret, as raw bytes. It must not be empty.</param>
	/// <param name="format">The code format, such as <c>OtpCodeFormat.Decimal(6)</c>.</param>
	/// <returns>An instance that holds a copy of the key.</returns>
	/// <exception cref="ArgumentException"><paramref name="key" /> is empty, or <paramref name="format" /> is the default value.</exception>
	/// <exception cref="NotSupportedException">The hash of <typeparamref name="TCore" /> is shorter than 20 bytes.</exception>
	public static Hotp<TCore> Create(ReadOnlySpan<byte> key, OtpCodeFormat format)
	{
		OtpKey<TCore>.ThrowIfInvalid(key, nameof(key));
		OtpCodeFormat.ThrowIfDefault(format, nameof(format));

		Hotp<TCore> hotp = new(format);
		hotp._key.Initialize(key);
		return hotp;
	}

	/// <summary>
	/// Generates the code for a counter.
	/// </summary>
	/// <param name="counter">The counter C.</param>
	/// <param name="destination">The buffer that receives the code, at least <c>Format.Length</c> characters long.</param>
	/// <returns>The number of characters written, which is <c>Format.Length</c>.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int Generate(ulong counter, Span<char> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, Format.Length, nameof(destination));

		_key.Generate(counter, Format, destination);
		return Format.Length;
	}

	/// <summary>
	/// Verifies a code against a counter and the counters that follow it, in constant time.
	/// </summary>
	/// <remarks>
	/// Every counter in the window is computed, so the cost grows with <paramref name="lookAhead" />. The window stops at <see cref="ulong.MaxValue" /> rather than wrapping.
	/// On success, set the stored counter to <paramref name="matchedCounter" /> + 1 so that no code at or before it is accepted again, in one atomic step that fails if the stored counter changed since it was read. A match at <see cref="ulong.MaxValue" /> has no next counter, so refuse it rather than let the counter wrap.
	/// </remarks>
	/// <param name="counter">The next counter the verifier expects.</param>
	/// <param name="code">The code to verify. A code of the wrong length does not match.</param>
	/// <param name="lookAhead">The number of counters after <paramref name="counter" /> also accepted, the look-ahead window s of RFC 4226 section 7.4. It must not be negative; 0 accepts <paramref name="counter" /> only.</param>
	/// <param name="matchedCounter">When this method returns <see langword="true" />, the lowest counter whose code matches; otherwise, 0.</param>
	/// <returns><see langword="true" /> if the code matches a counter in the window; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="lookAhead" /> is negative.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public bool Verify(ulong counter, ReadOnlySpan<char> code, int lookAhead, out ulong matchedCounter)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfNegative(lookAhead);

		ulong last = (ulong)lookAhead > ulong.MaxValue - counter ? ulong.MaxValue : counter + (ulong)lookAhead;
		return _key.Verify(counter, last, Format, code, out matchedCounter);
	}

	/// <summary>
	/// Erases the key.
	/// </summary>
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_key.ZeroMemory();
		_disposed = true;
	}
}
