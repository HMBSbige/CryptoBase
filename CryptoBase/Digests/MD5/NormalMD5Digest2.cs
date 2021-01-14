using System;
using System.Buffers;

namespace CryptoBase.Digests.MD5
{
	public class NormalMD5Digest2 : IHash
	{
		public string Name { get; } = @"MD5";

		private const byte Md5Len = NormalMD5Digest.Md5Len;

		public Span<byte> Compute(in ReadOnlySpan<byte> origin)
		{
			var buffer = ArrayPool<byte>.Shared.Rent(Md5Len);
			try
			{
				var span = buffer.AsSpan(0, Md5Len);

				System.Security.Cryptography.MD5.HashData(origin, span);

				return span;
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(buffer);
			}
		}
	}
}
