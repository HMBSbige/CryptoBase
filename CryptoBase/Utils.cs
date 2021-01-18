using Org.BouncyCastle.Crypto;
using System;
using System.Buffers;
using System.Security.Cryptography;

namespace CryptoBase
{
	public static class Utils
	{
		public static void RandBytes(Span<byte> buf)
		{
			using var rngServiceProvider = new RNGCryptoServiceProvider();
			rngServiceProvider.GetBytes(buf);
		}

		public static Span<byte> RandBytes(int size)
		{
			Span<byte> bytes = new byte[size];
			RandBytes(bytes);
			return bytes;
		}

		internal static void BcComputeHash(IDigest hash, int length, in ReadOnlySpan<byte> origin, Span<byte> destination)
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
	}
}
