using System;
using System.Buffers.Binary;
using System.Linq;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace CryptoBase
{
	public static class Extensions
	{
		private const string Alphabet = @"0123456789abcdef";

		#region SodiumIncrement

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
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

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static void IncrementUInt(this byte[] nonce)
		{
			var i = BinaryPrimitives.ReadUInt32LittleEndian(nonce);
			++i;
			BinaryPrimitives.WriteUInt32LittleEndian(nonce, i);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static unsafe void IncrementIntUnsafe(this byte[] nonce)
		{
			fixed (byte* p = nonce)
			{
				++*(uint*)p;
			}
		}

		/// <summary>
		/// https://github.com/jedisct1/libsodium/blob/master/src/libsodium/sodium/utils.c#L263
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static void IncrementSource(this byte[] nonce)
		{
			var i = 0U;
			ushort c = 1;
			for (; i < nonce.Length; i++)
			{
				c += nonce[i];
				nonce[i] = (byte)c;
				c >>= 8;
			}
		}

		#endregion

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static void IncrementBe(this byte[] counter)
		{
			var j = counter.Length;
			while (--j >= 0 && ++counter[j] == 0)
			{
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static void IncrementBe(this Span<byte> counter)
		{
			var j = counter.Length;
			while (--j >= 0 && ++counter[j] == 0)
			{
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static void IncrementBe4(this byte[] counter, int start, int end)
		{
			var j = end;
			if ((counter[--j] += 4) < 4)
			{
				while (--j >= start && ++counter[j] == 0)
				{
				}
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static void IncrementBe4(this Span<byte> counter)
		{
			var j = counter.Length;
			if ((counter[--j] += 4) < 4)
			{
				while (--j >= 0 && ++counter[j] == 0)
				{
				}
			}
		}

		public static string ToHex(this in Span<byte> bytes)
		{
			Span<char> c = stackalloc char[bytes.Length << 1];

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

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static uint RotateLeft(this uint value, int offset)
		{
			return BitOperations.RotateLeft(value, offset);
		}
	}
}
