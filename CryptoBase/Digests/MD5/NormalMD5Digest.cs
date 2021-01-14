using System;
using System.Buffers;
using System.Threading;

namespace CryptoBase.Digests.MD5
{
	public class NormalMD5Digest : IHash
	{
		public string Name { get; } = @"MD5";

		public const byte Md5Len = 16;
		private static readonly ThreadLocal<System.Security.Cryptography.MD5> Hasher = new(System.Security.Cryptography.MD5.Create);

		public Span<byte> Compute(in ReadOnlySpan<byte> origin)
		{
			var buffer = ArrayPool<byte>.Shared.Rent(Md5Len);
			try
			{
				var span = buffer.AsSpan(0, Md5Len);

				Hasher.Value!.TryComputeHash(origin, span, out _);

				return span;
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(buffer);
			}
		}
	}
}
