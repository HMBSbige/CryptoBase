using Org.BouncyCastle.Crypto;
using System;
using System.Buffers;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace CryptoBase.BouncyCastle
{
	public static class Extensions
	{
		internal static void BcComputeHash(this IDigest hash, int length, in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			var buffer = ArrayPool<byte>.Shared.Rent(origin.Length);
			var outBuffer = ArrayPool<byte>.Shared.Rent(length);
			try
			{
				origin.CopyTo(buffer);

				hash.Reset();
				hash.BlockUpdate(buffer, 0, origin.Length);
				hash.DoFinal(outBuffer, 0);

				outBuffer.AsSpan(0, length).CopyTo(destination);
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(buffer);
				ArrayPool<byte>.Shared.Return(outBuffer);
			}
		}

		internal static void BcUpdateStream(this IStreamCipher cipher, ReadOnlySpan<byte> source, Span<byte> destination)
		{
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
