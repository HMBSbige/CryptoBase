using CryptoBase.Encodings;
using System.Text;

namespace CryptoBase.Tests.Encodings;

public static class Base32TestUtils
{
	public const string LowercaseAlphabet = "abcdefghijklmnopqrstuvwxyz234567";

	public static string Rfc4648Alphabet(bool hex)
	{
		return hex ? "0123456789ABCDEFGHIJKLMNOPQRSTUV" : "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	}

	public static Base32Encoding Rfc4648Encoding(bool hex, bool omitPadding = false)
	{
		Base32Encoding encoding = hex ? Base32Encoding.Rfc4648Hex : Base32Encoding.Rfc4648;
		return omitPadding ? encoding.OmitPadding : encoding;
	}

	public static byte[] CreatePatternSource(int length, int offset)
	{
		byte[] source = new byte[length];

		for (int i = 0; i < source.Length; ++i)
		{
			source[i] = (byte)(i * 37 + offset);
		}

		return source;
	}

	public static char[] EncodeReference(ReadOnlySpan<byte> source, bool hex, bool omitPadding)
	{
		return EncodeReference(source, Rfc4648Alphabet(hex), '=', omitPadding);
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
