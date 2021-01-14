using System;
using System.Buffers;

namespace CryptoBase.Digests.MD5
{
	public class NormalMD5Digest : IHash
	{
		public string Name { get; } = @"MD5";

		public const byte Md5Len = 16;
		private readonly System.Security.Cryptography.MD5 _hasher;

		public NormalMD5Digest()
		{
			_hasher = System.Security.Cryptography.MD5.Create();
		}

		public Span<byte> Compute(in ReadOnlySpan<byte> origin)
		{
			var buffer = ArrayPool<byte>.Shared.Rent(Md5Len);
			try
			{
				var span = buffer.AsSpan(0, Md5Len);

				_hasher.TryComputeHash(origin, span, out _);

				return span;
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(buffer);
			}
		}
	}
}
