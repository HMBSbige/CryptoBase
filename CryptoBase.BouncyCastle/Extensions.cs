using Org.BouncyCastle.Crypto;
using System;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace CryptoBase.BouncyCastle
{
	public static class Extensions
	{
		internal static void BcUpdateStream(this IStreamCipher cipher, ReadOnlySpan<byte> source, Span<byte> destination)
		{
			if (destination.Length < source.Length)
			{
				throw new ArgumentException(string.Empty, nameof(destination));
			}

			for (var i = 0; i < source.Length; ++i)
			{
				destination[i] = cipher.ReturnByte(source[i]);
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		internal static uint RotateLeft(this uint value, int offset)
		{
			return BitOperations.RotateLeft(value, offset);
		}
	}
}
