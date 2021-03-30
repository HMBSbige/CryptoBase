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

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static void IncrementInternal(this Span<byte> nonce)
		{
			for (var i = 0; i < nonce.Length; ++i)
			{
				if (++nonce[i] != 0)
				{
					break;
				}
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Increment(this Span<byte> nonce)
		{
			nonce.IncrementInternal();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void Increment(this byte[] nonce)
		{
			IncrementInternal(nonce);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void IncrementUInt(this byte[] nonce)
		{
			var i = BinaryPrimitives.ReadUInt32LittleEndian(nonce);
			++i;
			BinaryPrimitives.WriteUInt32LittleEndian(nonce, i);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
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
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
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

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static void IncrementBeInternal(this Span<byte> counter)
		{
			var j = counter.Length;
			while (--j >= 0 && ++counter[j] == 0)
			{
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void IncrementBe(this byte[] counter)
		{
			IncrementBeInternal(counter);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void IncrementBe(this Span<byte> counter)
		{
			counter.IncrementBeInternal();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
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

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static uint RotateLeft(this uint value, int offset)
		{
			return BitOperations.RotateLeft(value, offset);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static int GetDeterministicHashCode(this string str)
		{
			unchecked
			{
				var hash1 = (5381 << 16) + 5381;
				var hash2 = hash1;

				for (var i = 0; i < str.Length; i += 2)
				{
					hash1 = ((hash1 << 5) + hash1) ^ str[i];
					if (i == str.Length - 1)
					{
						break;
					}

					hash2 = ((hash2 << 5) + hash2) ^ str[i + 1];
				}

				return hash1 + hash2 * 1566083941;
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static int GetDeterministicHashCode<T>(this ReadOnlySpan<T> span) where T : notnull
		{
			unchecked
			{
				var hash = 5381;

				foreach (var t in span)
				{
					hash = ((hash << 5) + hash) ^ t.GetHashCode();
				}

				return hash;
			}
		}
	}
}
