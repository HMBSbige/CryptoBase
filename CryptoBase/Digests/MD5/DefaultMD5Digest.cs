using CryptoBase.Abstractions.Digests;
using System;

namespace CryptoBase.Digests.MD5
{
	public class DefaultMD5Digest : MD5DigestBase
	{
		private readonly System.Security.Cryptography.MD5 _hasher = System.Security.Cryptography.MD5.Create();

		public override void ComputeHash(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			_hasher.TryComputeHash(origin, destination, out _);
		}
	}
}
