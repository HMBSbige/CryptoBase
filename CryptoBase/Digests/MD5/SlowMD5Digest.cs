using CryptoBase.Abstractions.Digests;
using System;
using System.Threading;

namespace CryptoBase.Digests.MD5
{
	public class SlowMD5Digest : MD5DigestBase
	{
		private static readonly ThreadLocal<IHash> Hasher = new(() => new SlowMD5DigestInternal());

		public override void ComputeHash(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Hasher.Value!.ComputeHash(origin, destination);
		}
	}
}
