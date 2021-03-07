using CryptoBase.Abstractions.Digests;
using System;
using System.Buffers;

namespace CryptoBase.Digests.SHA1
{
	public class DefaultSHA1Digest : IHash
	{
		private readonly System.Security.Cryptography.SHA1 _hasher = System.Security.Cryptography.SHA1.Create();

		public string Name => @"SHA-1";

		public int Length => HashConstants.Sha1Length;

		public void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination)
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

		public void Reset()
		{
			_hasher.TransformFinalBlock(Array.Empty<byte>(), 0, 0);
		}
	}
}
