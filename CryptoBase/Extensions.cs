using CryptoBase.Digests.MD5;
using System;

namespace CryptoBase
{
	public static class Extensions
	{
		private const string Alphabet = @"0123456789abcdef";

		public static void Increment(this byte[] nonce)
		{
			for (var i = 0; i < nonce.Length; ++i)
			{
				if (++nonce[i] != 0)
				{
					break;
				}
			}
		}

		public static void IncrementBe(this byte[] counter)
		{
			var j = counter.Length;
			while (--j >= 0 && ++counter[j] == 0)
			{ }
		}

		public static string ToHex(this in Span<byte> bytes)
		{
			Span<char> c = stackalloc char[NormalMD5Digest.Md5Len * 2];

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
	}
}
