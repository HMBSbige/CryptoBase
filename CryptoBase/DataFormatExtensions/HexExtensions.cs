using System;
using System.Runtime.CompilerServices;

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
	[SkipLocalsInit]
	public static string ToHex(this ReadOnlySpan<byte> bytes)
	{
		var length = bytes.Length << 1;
		var c = length switch
		{
			< 3 * 1024 / sizeof(char) => stackalloc char[length],
			_ => GC.AllocateUninitializedArray<char>(length)
		};

		var i = 0;
		var j = 0;

		while (i < bytes.Length)
		{
			var b = bytes[i++];
			c[j++] = Alphabet[b >> 4];
			c[j++] = Alphabet[b & 0xF];
		}

		var result = new string(c);

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

		var length = hex.Length >> 1;
		var buffer = GC.AllocateUninitializedArray<byte>(length);

		for (int i = 0, j = 0; i < length; ++i, ++j)
		{
			// Convert first half of byte
			var c = hex[j];
			buffer[i] = (byte)((c > '9' ? (c > 'Z' ? (c - 'a' + 10) : (c - 'A' + 10)) : (c - '0')) << 4);

			// Convert second half of byte
			c = hex[++j];
			buffer[i] |= (byte)(c > '9' ? (c > 'Z' ? (c - 'a' + 10) : (c - 'A' + 10)) : (c - '0'));
		}

		return buffer;
	}
}
