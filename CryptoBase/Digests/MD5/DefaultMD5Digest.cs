using CryptoBase.Abstractions.Digests;
using System;
using System.Buffers;

namespace CryptoBase.Digests.MD5
{
	public class DefaultMD5Digest : IHash
	{
		private readonly System.Security.Cryptography.MD5 _hasher = System.Security.Cryptography.MD5.Create();

		public string Name => @"MD5";

		public int Length => HashConstants.Md5Length;

		public void UpdateFinal(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			_hasher.TryComputeHash(origin, destination, out _);
		}

		public void Update(ReadOnlySpan<byte> source)
		{
			var buffer = ArrayPool<byte>.Shared.Rent(source.Length);
			try
			{
				source.CopyTo(buffer);
				_hasher.TransformBlock(buffer, 0, source.Length, default, default);
			}
			finally
			{
				ArrayPool<byte>.Shared.Return(buffer);
			}
		}

		public void GetHash(Span<byte> destination)
		{
			UpdateFinal(Array.Empty<byte>(), destination);
		}

		public void Dispose()
		{
			_hasher.Dispose();
		}

		public void Reset()
		{
			_hasher.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
		}
	}
}
