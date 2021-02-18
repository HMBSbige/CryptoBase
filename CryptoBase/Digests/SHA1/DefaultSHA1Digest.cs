using CryptoBase.Abstractions.Digests;
using System;

namespace CryptoBase.Digests.SHA1
{
	public class DefaultSHA1Digest : SHA1DigestBase
	{
		private readonly System.Security.Cryptography.SHA1 _hasher = System.Security.Cryptography.SHA1.Create();

		public override void ComputeHash(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			_hasher.TryComputeHash(origin, destination, out _);
		}
	}
}
