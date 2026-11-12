using System.Runtime.CompilerServices;

namespace CryptoBase.X509;

// The Time of RFC 5280, Sec. 4.1.2.5: UTCTime for the years 1950 through 2049 and GeneralizedTime for the others, both in UTC to the second.
internal static class X509Time
{
	private const int TwoDigitYearMax = 2049;
	private const byte UtcTimeTag = 0x17;
	private const byte GeneralizedTimeTag = 0x18;
	private const int UtcTimeLength = 13;
	private const int GeneralizedTimeLength = 15;

	// The days of each month in a year that is not a leap year; the 29th of February is left to ValueAsnReader.
	private static ReadOnlySpan<byte> DaysInMonth => [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

	// DER requires UTC with seconds, and puts a fraction of GeneralizedTime after a period, which RFC 5280 forbids.
	public static DateTimeOffset Read(ref DerReader reader)
	{
		ReadOnlySpan<byte> encoded = reader.ReadEncodedValue().Span;

		if (TryReadUtcTime(encoded, out int year, out int month, out int day, out int hour, out int minute, out int second))
		{
			return new DateTimeOffset(year, month, day, hour, minute, second, TimeSpan.Zero);
		}

		return ReadOther(encoded);
	}

	// As Read, for a time whose value the caller does not use, such as the revocation dates of a CRL.
	public static void Skip(ref DerReader reader)
	{
		ReadOnlySpan<byte> encoded = reader.ReadEncodedValue().Span;

		if (!TryReadUtcTime(encoded, out _, out _, out _, out _, out _, out _))
		{
			ReadOther(encoded);
		}
	}

	private static DateTimeOffset ReadOther(ReadOnlySpan<byte> encoded)
	{
		Asn1Tag tag = Asn1Tag.Decode(encoded, out _);

		if (tag == Asn1Tag.UtcTime)
		{
			// The default two-digit year maximum is TwoDigitYearMax.
			return new ValueAsnReader(encoded, AsnEncodingRules.DER).ReadUtcTime();
		}

		if (tag != Asn1Tag.GeneralizedTime)
		{
			throw new AsnContentException();
		}

		return ReadGeneralizedTime(encoded);
	}

	// A GeneralizedTime alone, as RFC 5280, Sec. 4.1.2.5.2, profiles it, for the fields that have no UTCTime alternative, such as those of OCSP (RFC 6960, Sec. 4.2.2.1).
	public static DateTimeOffset ReadGeneralizedTime(ref DerReader reader)
	{
		return ReadGeneralizedTime(reader.ReadEncodedValue().Span);
	}

	private static DateTimeOffset ReadGeneralizedTime(ReadOnlySpan<byte> encoded)
	{
		if (encoded.Length is GeneralizedTimeLength + 2 && encoded[0] is GeneralizedTimeTag && encoded[1] is GeneralizedTimeLength && TryParseGeneralizedTime(encoded.Slice(2), out DateTimeOffset value))
		{
			return value;
		}

		ValueAsnReader reader = new(encoded, AsnEncodingRules.DER);
		ReadOnlySpan<byte> contents = reader.PeekContentBytes();
		value = reader.ReadGeneralizedTime();

		if (contents.Contains((byte)'.'))
		{
			throw new AsnContentException();
		}

		return value;
	}

	public static DateTimeOffset TruncateToSeconds(DateTimeOffset value)
	{
		DateTimeOffset utc = value.ToUniversalTime();
		return utc.AddTicks(-(utc.Ticks % TimeSpan.TicksPerSecond));
	}

	// A whole UTCTime in the form YYMMDDHHMMSSZ, the only one that DER allows, with the date and time that TryParseDateAndTime accepts; anything else, valid or not, is left to ValueAsnReader.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool TryReadUtcTime(ReadOnlySpan<byte> encoded, out int year, out int month, out int day, out int hour, out int minute, out int second)
	{
		(year, month, day, hour, minute, second) = (0, 0, 0, 0, 0, 0);

		if (encoded.Length is not UtcTimeLength + 2 || encoded[0] is not UtcTimeTag || encoded[1] is not UtcTimeLength || encoded[14] is not (byte)'Z')
		{
			return false;
		}

		year = ReadTwoDigits(encoded[2], encoded[3]);

		if (year > 99 || !TryParseDateAndTime(encoded.Slice(4, 10), out month, out day, out hour, out minute, out second))
		{
			return false;
		}

		year += year > TwoDigitYearMax % 100 ? 1900 : 2000;
		return true;
	}

	// The contents of a GeneralizedTime in the form that RFC 5280, Sec. 4.1.2.5.2, requires, YYYYMMDDHHMMSSZ, with the date and time that TryParseDateAndTime accepts; anything else, valid or not, is left to ValueAsnReader.
	private static bool TryParseGeneralizedTime(ReadOnlySpan<byte> contents, out DateTimeOffset value)
	{
		value = default;

		if (contents.Length is not GeneralizedTimeLength || contents[14] is not (byte)'Z')
		{
			return false;
		}

		int century = ReadTwoDigits(contents[0], contents[1]);
		int year = ReadTwoDigits(contents[2], contents[3]);

		if (century > 99 || year > 99 || (century | year) is 0 || !TryParseDateAndTime(contents.Slice(4, 10), out int month, out int day, out int hour, out int minute, out int second))
		{
			return false;
		}

		value = new DateTimeOffset(century * 100 + year, month, day, hour, minute, second, TimeSpan.Zero);
		return true;
	}

	// The ten digits MMDDHHMMSS of a date that every year has and a time of 00:00:00 to 23:59:59; the 29th of February and anything else, valid or not, are left to ValueAsnReader.
	private static bool TryParseDateAndTime(ReadOnlySpan<byte> digits, out int month, out int day, out int hour, out int minute, out int second)
	{
		month = ReadTwoDigits(digits[0], digits[1]);
		day = ReadTwoDigits(digits[2], digits[3]);
		hour = ReadTwoDigits(digits[4], digits[5]);
		minute = ReadTwoDigits(digits[6], digits[7]);
		second = ReadTwoDigits(digits[8], digits[9]);

		return (uint)(month - 1) < 12 && (uint)(day - 1) < DaysInMonth[month - 1] && hour < 24 && minute < 60 && second < 60;
	}

	// Two ASCII digits as a number, or a value above 99 if they are not digits.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int ReadTwoDigits(byte tens, byte ones)
	{
		uint first = (uint)tens - '0';
		uint second = (uint)ones - '0';
		return first <= 9 && second <= 9 ? (int)(first * 10 + second) : 100;
	}

	// value is in UTC and has no fractional seconds.
	public static void Write(AsnWriter writer, DateTimeOffset value)
	{
		Debug.Assert(value.Offset == TimeSpan.Zero && value.Ticks % TimeSpan.TicksPerSecond is 0);

		if (value.Year is >= TwoDigitYearMax - 99 and <= TwoDigitYearMax)
		{
			writer.WriteUtcTime(value, TwoDigitYearMax);
		}
		else
		{
			writer.WriteGeneralizedTime(value, omitFractionalSeconds: true);
		}
	}
}
