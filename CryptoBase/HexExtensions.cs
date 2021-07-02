using System;
using System.Linq;

namespace CryptoBase
{
	public static class HexExtensions
	{
		private const string Alphabet = @"0123456789abcdef";

		public static string ToHex(this in Span<byte> bytes)
		{
			var length = bytes.Length << 1;
			Span<char> c = length switch
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
			return Enumerable.Range(0, hex.Length)
					.Where(x => (x & 1) == 0)
					.Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
					.ToArray();
		}
	}
}
