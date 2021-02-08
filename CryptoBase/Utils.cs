using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace CryptoBase
{
	public static class Utils
	{
		public static Span<byte> RandBytes(int size)
		{
			Span<byte> bytes = new byte[size];
			RandomNumberGenerator.Fill(bytes);
			return bytes;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		public static void Swap<T>(ref T a, ref T b)
		{
			var t = a;
			a = b;
			b = t;
		}

		public static unsafe void FastCopy(byte* source, byte* destination, int count)
		{
			while (count >= 8)
			{
				*(ulong*)destination = *(ulong*)source;
				destination += 8;
				source += 8;
				count -= 8;
			}

			if (count >= 4)
			{
				*(uint*)destination = *(uint*)source;
				destination += 4;
				source += 4;
				count -= 4;
			}

			if (count >= 2)
			{
				*(ushort*)destination = *(ushort*)source;
				destination += 2;
				source += 2;
				count -= 2;
			}

			if (count >= 1)
			{
				*destination = *source;
			}
		}
	}
}
