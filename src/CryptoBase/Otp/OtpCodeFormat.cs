namespace CryptoBase.Otp;

/// <summary>
/// Represents how a one-time password is written: as decimal digits, as specified by RFC 4226, or as a Steam Guard code.
/// </summary>
/// <remarks>
/// The default value is not a valid format.
/// </remarks>
public readonly record struct OtpCodeFormat
{
	private const int MinDigits = 6;
	private const int MaxDigits = 9;

	private const int SteamGuardLength = 5;
	private const string SteamGuardAlphabet = "23456789BCDFGHJKMNPQRTVWXY";
	private const uint SteamGuardRadix = 26;

	private OtpCodeFormat(int length, bool isSteamGuard)
	{
		Length = length;
		IsSteamGuard = isSteamGuard;
	}

	/// <summary>
	/// Gets the format of Steam Guard codes: five characters from <c>23456789BCDFGHJKMNPQRTVWXY</c>.
	/// </summary>
	/// <remarks>
	/// Steam Guard computes the HMAC with SHA-1; see <see cref="TotpParameters.SteamGuard" />.
	/// </remarks>
	public static OtpCodeFormat SteamGuard => new(SteamGuardLength, true);

	/// <summary>
	/// Gets the number of characters in a code.
	/// </summary>
	public int Length { get; }

	private bool IsSteamGuard { get; }

	/// <summary>
	/// Gets a format of decimal digits, as specified by RFC 4226, padded on the left with zeros.
	/// </summary>
	/// <param name="digits">The number of digits, from 6 to 9.</param>
	/// <returns>The format.</returns>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="digits" /> is less than 6 or greater than 9.</exception>
	public static OtpCodeFormat Decimal(int digits)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(digits, MinDigits);
		ArgumentOutOfRangeException.ThrowIfGreaterThan(digits, MaxDigits);

		return new OtpCodeFormat(digits, false);
	}

	internal static void ThrowIfDefault(OtpCodeFormat format, string? paramName)
	{
		if (format.Length is 0)
		{
			throw new ArgumentException("The format must be OtpCodeFormat.Decimal or OtpCodeFormat.SteamGuard.", paramName);
		}
	}

	internal void Write(uint value, Span<char> destination)
	{
		Debug.Assert(destination.Length >= Length);

		if (IsSteamGuard)
		{
			for (int i = 0; i < Length; ++i)
			{
				destination[i] = SteamGuardAlphabet[(int)(value % SteamGuardRadix)];
				value /= SteamGuardRadix;
			}

			return;
		}

		for (int i = Length - 1; i >= 0; --i)
		{
			destination[i] = (char)('0' + value % 10);
			value /= 10;
		}
	}
}
