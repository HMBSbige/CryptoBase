using CryptoBase.Abstractions.Digests;
using System;
using System.Threading;

namespace CryptoBase.Digests.SHA1
{
	public class NormalSHA1Digest : SHA1DigestBase
	{
		private static readonly ThreadLocal<System.Security.Cryptography.SHA1> Hasher = new(System.Security.Cryptography.SHA1.Create);

		public override void ComputeHash(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Hasher.Value!.TryComputeHash(origin, destination, out _);
		}
	}
}
