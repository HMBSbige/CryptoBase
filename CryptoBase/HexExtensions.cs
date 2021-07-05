using System;

namespace CryptoBase
{
	public static class HexExtensions
	{
		private const string Alphabet = @"0123456789abcdef";

		public static string ToHex(this in Span<byte> bytes)
		{
			return ToHex((ReadOnlySpan<byte>)bytes);
		}

		public static string ToHex(this in ReadOnlySpan<byte> bytes)
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

		public static byte[] FromHex(this string hex)
		{
			hex = hex.Replace(@"0x", string.Empty).Replace(@"-", string.Empty);

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
}
