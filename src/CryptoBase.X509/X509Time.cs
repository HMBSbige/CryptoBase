namespace CryptoBase.X509;

// The Time of RFC 5280, Sec. 4.1.2.5: UTCTime for the years 1950 through 2049 and GeneralizedTime for the others, both in UTC to the second.
internal static class X509Time
{
	private const int TwoDigitYearMax = 2049;

	// DER requires UTC with seconds, and puts a fraction of GeneralizedTime after a period, which RFC 5280 forbids.
	public static DateTimeOffset Read(ref DerReader reader)
	{
		ReadOnlySpan<byte> encoded = reader.ReadEncodedValue().Span;
		Asn1Tag tag = Asn1Tag.Decode(encoded, out _);

		if (tag == Asn1Tag.UtcTime)
		{
			// The default two-digit year maximum is TwoDigitYearMax.
			return AsnDecoder.ReadUtcTime(encoded, AsnEncodingRules.DER, out _);
		}

		if (tag != Asn1Tag.GeneralizedTime)
		{
			throw new AsnContentException();
		}

		DateTimeOffset value = AsnDecoder.ReadGeneralizedTime(encoded, AsnEncodingRules.DER, out _);
		AsnDecoder.ReadEncodedValue(encoded, AsnEncodingRules.DER, out int offset, out int length, out _);

		if (encoded.Slice(offset, length).Contains((byte)'.'))
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
