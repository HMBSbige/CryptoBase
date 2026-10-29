namespace CryptoBase.Internal;

// Finds the PEM blocks of RFC 7468 in order; text outside them is skipped.
internal ref struct PemReader(ReadOnlySpan<char> source)
{
	private ReadOnlySpan<char> _remaining = source;

	public bool TryRead(out ReadOnlySpan<char> label, out ReadOnlySpan<char> base64Data, out int decodedLength)
	{
		if (!PemEncoding.TryFind(_remaining, out PemFields fields))
		{
			label = default;
			base64Data = default;
			decodedLength = 0;
			return false;
		}

		label = Slice(_remaining, fields.Label);
		base64Data = Slice(_remaining, fields.Base64Data);
		decodedLength = fields.DecodedDataLength;
		_remaining = _remaining.Slice(fields.Location.End.GetOffset(_remaining.Length));
		return true;
	}

	// base64Data comes from TryRead, where PemEncoding has validated it, so it decodes into exactly decodedLength bytes.
	public static void Decode(ReadOnlySpan<char> base64Data, Span<byte> destination)
	{
		bool decoded = Convert.TryFromBase64Chars(base64Data, destination, out int written);
		Debug.Assert(decoded && written == destination.Length);
	}

	private static ReadOnlySpan<char> Slice(ReadOnlySpan<char> source, Range range)
	{
		(int offset, int length) = range.GetOffsetAndLength(source.Length);
		return source.Slice(offset, length);
	}
}
