using Org.BouncyCastle.Crypto;
using System;
using System.Buffers;
using System.Numerics;
using System.Runtime.CompilerServices;

namespace CryptoBase.BouncyCastle
{
	public static class Extensions
	{
		internal static void BcHashUpdateFinal(this IDigest hash, int length, in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			hash.BcHashUpdate(origin);
			hash.BcGetHash(length, destination);
		}

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

		internal static void BcHashUpdate(this IDigest hash, in ReadOnlySpan<byte> origin)
		{
			var buffer = ArrayPool<byte>.Shared.Rent(origin.Length);
			try
			{
				origin.CopyTo(buffer);
				hash.BlockUpdate(buffer, 0, origin.Length);
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(buffer);
			}
		}

		internal static void BcGetHash(this IDigest hash, int length, Span<byte> destination)
		{
			var outBuffer = ArrayPool<byte>.Shared.Rent(length);
			try
			{
				hash.DoFinal(outBuffer, 0);
				outBuffer.AsSpan(0, length).CopyTo(destination);
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(outBuffer);
			}
		}
	}
}
