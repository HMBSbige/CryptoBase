namespace CryptoBase.DataFormatExtensions;

/// <summary>
/// https://datatracker.ietf.org/doc/html/rfc4648
/// </summary>
public static class Base32Extensions
{
	#region Table

	private const string Alphabet = @"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	private const char PaddingChar = '=';
	private static readonly int[] Table = BuildTable();
	private static int[] BuildTable()
	{
		var res = new int[sbyte.MaxValue];
		var span = res.AsSpan();
		span.Fill(-1);

		var i = 0;
		foreach (var c in Alphabet)
		{
			span[c] = i++;
		}

		return res;
	}

	private const int Mask = 31;
	private const int Shift = 5;
	private const int BitsPerByte = 8;

	#endregion

	public static string ToBase32String(this Span<byte> data)
	{
		return ((ReadOnlySpan<byte>)data).ToBase32String();
	}

	public static string ToBase32String(this ReadOnlySpan<byte> data)
	{
		if (data.IsEmpty)
		{
			return string.Empty;
		}

		var length = data.Length;

		if (length >= 1 << 28)
		{
			throw new ArgumentOutOfRangeException(nameof(data));
		}

		var outLength = ((length - 1) / Shift + 1) << 3;
		var result = new string('\0', outLength);
		ref var firstCh = ref Unsafe.AsRef(result.GetPinnableReference());

		var offset = 0;
		var i = 0;
		int buffer = data[offset++];
		var bitsLeft = 8;
		while (bitsLeft > 0 || offset < length)
		{
			if (bitsLeft < Shift)
			{
				if (offset < length)
				{
					buffer <<= BitsPerByte;
					buffer |= data[offset++];
					bitsLeft += BitsPerByte;
				}
				else
				{
					var pad = Shift - bitsLeft;
					buffer <<= pad;
					bitsLeft += pad;
				}
			}
			var index = Mask & buffer >> bitsLeft - Shift;
			bitsLeft -= Shift;
			Unsafe.Add(ref firstCh, i++) = Alphabet[index];
		}

		for (; i < outLength; ++i)
		{
			Unsafe.Add(ref firstCh, i) = PaddingChar;
		}

		return result;
	}

	public static byte[] FromBase32String(this string encoded)
	{
		return encoded.AsSpan().FromBase32String();
	}

	public static byte[] FromBase32String(this ReadOnlySpan<char> encoded)
	{
		encoded = encoded.TrimEnd(PaddingChar);
		if (encoded.IsEmpty)
		{
			return Array.Empty<byte>();
		}

		var outLength = encoded.Length * Shift >> 3;
		var result = new byte[outLength];
		var buffer = 0;
		var i = 0;
		var bitsLeft = 0;
		foreach (var c in encoded)
		{
			var value = Table[c];
			if (value < 0)
			{
				throw new FormatException($@"Illegal character: '{c}'");
			}

			buffer <<= Shift;
			buffer |= value;
			bitsLeft += Shift;
			if (bitsLeft >= BitsPerByte)
			{
				bitsLeft -= BitsPerByte;
				result[i++] = (byte)(buffer >> bitsLeft);
			}
		}

		return result;
	}
}
