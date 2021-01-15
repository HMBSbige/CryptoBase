using CryptoBase.Digests.MD5;
using System;

namespace CryptoBase
{
	public static class Extensions
	{
		private const string Alphabet = @"0123456789abcdef";

		#region SodiumIncrement

		public static unsafe void Increment_Int(this byte[] nonce)
		{
			fixed (byte* pNonce = nonce)
			{
				var value = (int*)pNonce;
				++*value;
			}
		}

		public static void Increment_Int2(this byte[] data)
		{
			if (++data[0] != 0)
			{
				return;
			}

			if (++data[1] != 0)
			{
				return;
			}

			if (++data[2] != 0)
			{
				return;
			}

			++data[3];
		}

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

		public static void FastIntIncrement(this byte[] nonce)
		{
			nonce.Increment_Int2();
		}

		#endregion

		#region SodiumIncrementBE

		public static void IncrementBe(this byte[] counter)
		{
			var j = counter.Length;
			while (--j >= 0 && ++counter[j] == 0)
			{ }
		}

		#endregion

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
