namespace CryptoBase.Otp;

/// <summary>
/// Represents the system parameters of TOTP, as specified by RFC 6238: the code format, the time step X and the initial time T0.
/// </summary>
/// <remarks>
/// The hash function is not a parameter here but the type argument of <see cref="Totp{TCore}" />.
/// The default value is not valid.
/// </remarks>
public readonly record struct TotpParameters
{
	private const int DefaultTimeStepSeconds = 30;

	private static readonly long MinUnixTime = DateTimeOffset.MinValue.ToUnixTimeSeconds();
	private static readonly long MaxUnixTime = DateTimeOffset.MaxValue.ToUnixTimeSeconds();

	/// <summary>
	/// Initializes a new instance of the <see cref="TotpParameters" /> struct.
	/// </summary>
	/// <param name="format">The code format.</param>
	/// <param name="timeStepSeconds">The time step X, in seconds. It must be at least 1.</param>
	/// <param name="initialUnixTime">The Unix time T0 from which time steps are counted, in seconds. It must lie within the range of <see cref="DateTimeOffset" />.</param>
	/// <exception cref="ArgumentException"><paramref name="format" /> is the default value.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="timeStepSeconds" /> is less than 1, or <paramref name="initialUnixTime" /> is outside the range of <see cref="DateTimeOffset" />.</exception>
	public TotpParameters(OtpCodeFormat format, int timeStepSeconds = DefaultTimeStepSeconds, long initialUnixTime = 0)
	{
		OtpCodeFormat.ThrowIfDefault(format, nameof(format));
		ArgumentOutOfRangeException.ThrowIfLessThan(timeStepSeconds, 1);
		ArgumentOutOfRangeException.ThrowIfLessThan(initialUnixTime, MinUnixTime);
		ArgumentOutOfRangeException.ThrowIfGreaterThan(initialUnixTime, MaxUnixTime);

		Format = format;
		TimeStepSeconds = timeStepSeconds;
		InitialUnixTime = initialUnixTime;
	}

	/// <summary>
	/// Gets the defaults of RFC 6238: six decimal digits, X = 30 seconds and T0 = 0.
	/// </summary>
	public static TotpParameters Rfc6238 => new(OtpCodeFormat.Decimal(6));

	/// <summary>
	/// Gets the parameters of Steam Guard: <see cref="OtpCodeFormat.SteamGuard" />, X = 30 seconds and T0 = 0. Use them with <c>Totp&lt;Sha1Core&gt;</c>.
	/// </summary>
	public static TotpParameters SteamGuard => new(OtpCodeFormat.SteamGuard);

	/// <summary>
	/// Gets the code format.
	/// </summary>
	public OtpCodeFormat Format { get; }

	/// <summary>
	/// Gets the time step X, in seconds.
	/// </summary>
	public int TimeStepSeconds { get; }

	/// <summary>
	/// Gets the Unix time T0 from which time steps are counted, in seconds.
	/// </summary>
	public long InitialUnixTime { get; }

	/// <summary>
	/// Gets the time step T that contains a time: floor((Unix time - T0) / X).
	/// </summary>
	/// <param name="time">The time. Fractions of a second are discarded.</param>
	/// <returns>The time step, which is also the HOTP counter.</returns>
	/// <exception cref="ArgumentException">The parameters are the default value.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="time" /> is earlier than T0.</exception>
	public long GetTimeStep(DateTimeOffset time)
	{
		ThrowIfDefault(this, null);

		long elapsed = time.ToUnixTimeSeconds() - InitialUnixTime;

		if (elapsed < 0)
		{
			throw new ArgumentOutOfRangeException(nameof(time), time, "The time must not be earlier than the initial time T0.");
		}

		return elapsed / TimeStepSeconds;
	}

	internal static void ThrowIfDefault(TotpParameters parameters, string? paramName)
	{
		if (parameters.TimeStepSeconds is 0)
		{
			throw new ArgumentException("The parameters must be created by a TotpParameters constructor.", paramName);
		}
	}
}
