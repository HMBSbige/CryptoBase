using CryptoBase.Abstractions.Digests;
using System;
using System.Threading;

namespace CryptoBase.Digests.SM3
{
	public class SlowSM3Digest : SM3DigestBase
	{
		private static readonly ThreadLocal<IHash> Hasher = new(() => new SlowSM3DigestInternal());

		public override void ComputeHash(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Hasher.Value!.ComputeHash(origin, destination);
		}
	}
}
