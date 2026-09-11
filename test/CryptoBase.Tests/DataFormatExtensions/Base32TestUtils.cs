using System.Text;

namespace CryptoBase.Tests.DataFormatExtensions;

public static class Base32TestUtils
{
	public static char[] EncodeReference(ReadOnlySpan<byte> source, bool hex, bool omitPadding)
	{
		const string rfc4648 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
		const string rfc4648Hex = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
		return EncodeReference(source, hex ? rfc4648Hex : rfc4648, '=', omitPadding);
	}

	public static char[] EncodeReference(ReadOnlySpan<byte> source, string alphabet, char padding, bool omitPadding)
	{
		int resultLength = omitPadding
			? (source.Length * 8 + 4) / 5
			: (source.Length + 4) / 5 * 8;
		char[] result = new char[resultLength];
		int buffer = 0;
		int bits = 0;
		int offset = 0;

		foreach (byte value in source)
		{
			buffer = buffer << 8 | value;
			bits += 8;

			while (bits >= 5)
			{
				bits -= 5;
				result[offset++] = alphabet[buffer >> bits & 31];
			}
		}

		if (bits is not 0)
		{
			result[offset++] = alphabet[buffer << 5 - bits & 31];
		}

		while (!omitPadding && offset < result.Length)
		{
			result[offset++] = padding;
		}

		return result;
	}

	public static byte[] ToByteSymbols(ReadOnlySpan<char> source)
	{
		byte[] result = new byte[source.Length];
		Encoding.Latin1.GetBytes(source, result);
		return result;
	}
}
