namespace CryptoBase.DataFormatExtensions;

public static class HexExtensions
{
	private const string Alphabet = @"0123456789abcdef";

	/// <summary>
	/// Converts a span of 8-bit unsigned integers to its equivalent string representation that is encoded with lowercase hex characters.
	/// </summary>
	public static string ToHex(this Span<byte> bytes)
	{
		return ToHex((ReadOnlySpan<byte>)bytes);
	}

	/// <summary>
	/// Converts a span of 8-bit unsigned integers to its equivalent string representation that is encoded with lowercase hex characters.
	/// </summary>
	public static string ToHex(this ReadOnlySpan<byte> bytes)
	{
		int length = bytes.Length << 1;
		string result = new('\0', length);

		ref char firstCh = ref Unsafe.AsRef(in result.GetPinnableReference());

		int i = 0;
		int j = 0;

		while (i < bytes.Length)
		{
			byte b = bytes[i++];
			Unsafe.Add(ref firstCh, j++) = Alphabet[b >> 4];
			Unsafe.Add(ref firstCh, j++) = Alphabet[b & 0xF];
		}

		return result;
	}

	/// <summary>
	/// Converts a span of 8-bit unsigned integers to its equivalent string representation that is encoded with uppercase hex characters.
	/// </summary>
	public static string ToHexString(this Span<byte> bytes)
	{
		return Convert.ToHexString(bytes);
	}

	/// <summary>
	/// Converts a span of 8-bit unsigned integers to its equivalent string representation that is encoded with uppercase hex characters.
	/// </summary>
	public static string ToHexString(this ReadOnlySpan<byte> bytes)
	{
		return Convert.ToHexString(bytes);
	}

	/// <summary>
	/// Converts the specified string, which encodes binary data as hex characters, to an equivalent 8-bit unsigned integer array.
	/// </summary>
	public static byte[] FromHex(this string hex)
	{
		return hex.AsSpan().FromHex();
	}

	/// <summary>
	/// Converts the span, which encodes binary data as hex characters, to an equivalent 8-bit unsigned integer array.
	/// </summary>
	public static byte[] FromHex(this ReadOnlySpan<char> hex)
	{
		if ((hex.Length & 1) is not 0)
		{
			throw new ArgumentException($@"{nameof(hex)} length must be even");
		}

		int length = hex.Length >> 1;
		byte[] buffer = GC.AllocateUninitializedArray<byte>(length);

		for (int i = 0, j = 0; i < length; ++i, ++j)
		{
			// Convert first half of byte
			char c = hex[j];
			buffer[i] = (byte)((c > '9' ? (c > 'Z' ? (c - 'a' + 10) : (c - 'A' + 10)) : (c - '0')) << 4);

			// Convert second half of byte
			c = hex[++j];
			buffer[i] |= (byte)(c > '9' ? (c > 'Z' ? (c - 'a' + 10) : (c - 'A' + 10)) : (c - '0'));
		}

		return buffer;
	}
}
