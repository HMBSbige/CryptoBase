namespace CryptoBase.Otp;

/// <summary>
/// Generates and verifies time-based one-time passwords (TOTP), as specified by RFC 6238, including Steam Guard codes.
/// </summary>
/// <remarks>
/// <para>
/// A code is the <see cref="Hotp{TCore}" /> code whose counter is the time step that <see cref="TotpParameters.GetTimeStep" /> returns.
/// </para>
/// <para>
/// The methods take the time explicitly; pass <see cref="DateTimeOffset.UtcNow" /> or the time of a <see cref="TimeProvider" />.
/// <see cref="Generate" /> and <see cref="Verify" /> do not change the instance, so they may be called concurrently.
/// </para>
/// </remarks>
/// <typeparam name="TCore">
/// The hash core of the HMAC: <c>Sha1Core</c>, <c>Sha256Core</c> or <c>Sha512Core</c> in RFC 6238, and <c>Sha1Core</c> for Steam Guard. Its output must be at least 20 bytes long.
/// </typeparam>
public sealed class Totp<TCore> : IDisposable where TCore : unmanaged, IHmacHashCore<TCore>
{
	private OtpKey<TCore> _key;
	private bool _disposed;

	private Totp(TotpParameters parameters)
	{
		Parameters = parameters;
	}

	/// <summary>
	/// Gets the parameters.
	/// </summary>
	public TotpParameters Parameters { get; }

	/// <summary>
	/// Creates an instance that holds a key.
	/// </summary>
	/// <param name="key">The shared secret, as raw bytes. It must not be empty.</param>
	/// <param name="parameters">The parameters, such as <see cref="TotpParameters.Rfc6238" /> or <see cref="TotpParameters.SteamGuard" />.</param>
	/// <returns>An instance that holds a copy of the key.</returns>
	/// <exception cref="ArgumentException"><paramref name="key" /> is empty, or <paramref name="parameters" /> is the default value.</exception>
	/// <exception cref="NotSupportedException">The hash of <typeparamref name="TCore" /> is shorter than 20 bytes.</exception>
	public static Totp<TCore> Create(ReadOnlySpan<byte> key, TotpParameters parameters)
	{
		OtpKey<TCore>.ThrowIfInvalid(key, nameof(key));
		TotpParameters.ThrowIfDefault(parameters, nameof(parameters));

		Totp<TCore> totp = new(parameters);
		totp._key.Initialize(key);
		return totp;
	}

	/// <summary>
	/// Generates the code for a time.
	/// </summary>
	/// <param name="time">The time. Fractions of a second are discarded.</param>
	/// <param name="destination">The buffer that receives the code, at least <c>Parameters.Format.Length</c> characters long.</param>
	/// <returns>The number of characters written, which is <c>Parameters.Format.Length</c>.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="time" /> is earlier than T0.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public int Generate(DateTimeOffset time, Span<char> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		OtpCodeFormat format = Parameters.Format;
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, format.Length, nameof(destination));

		_key.Generate((ulong)Parameters.GetTimeStep(time), format, destination);
		return format.Length;
	}

	/// <summary>
	/// Verifies a code against the time step of a time and the steps around it, in constant time.
	/// </summary>
	/// <remarks>
	/// Every step in the window is computed, so the cost grows with the window. Steps before 0 are left out of the window.
	/// To keep a code from being accepted twice, store <paramref name="timeStep" /> on success and reject a later match at or before it, checking and storing in one atomic step.
	/// </remarks>
	/// <param name="time">The time the code was received. Fractions of a second are discarded.</param>
	/// <param name="code">The code to verify. A code of the wrong length does not match.</param>
	/// <param name="stepsBefore">The number of steps before the current one also accepted, for clock drift and transmission delay. It must not be negative.</param>
	/// <param name="stepsAfter">The number of steps after the current one also accepted, for a prover whose clock runs ahead. It must not be negative.</param>
	/// <param name="timeStep">When this method returns <see langword="true" />, the earliest time step whose code matches; otherwise, 0.</param>
	/// <returns><see langword="true" /> if the code matches a step in the window; otherwise, <see langword="false" />.</returns>
	/// <exception cref="ArgumentOutOfRangeException">
	/// <paramref name="time" /> is earlier than T0, or <paramref name="stepsBefore" /> or <paramref name="stepsAfter" /> is negative.
	/// </exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public bool Verify(DateTimeOffset time, ReadOnlySpan<char> code, int stepsBefore, int stepsAfter, out long timeStep)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfNegative(stepsBefore);
		ArgumentOutOfRangeException.ThrowIfNegative(stepsAfter);

		// T is below 2^39, so neither end overflows.
		long current = Parameters.GetTimeStep(time);
		long first = Math.Max(current - stepsBefore, 0);
		long last = current + stepsAfter;

		bool matched = _key.Verify((ulong)first, (ulong)last, Parameters.Format, code, out ulong matchedStep);
		timeStep = (long)matchedStep;
		return matched;
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
