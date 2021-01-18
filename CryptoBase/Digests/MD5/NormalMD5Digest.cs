using CryptoBase.Abstractions.Digests;
using System;
using System.Threading;

namespace CryptoBase.Digests.MD5
{
	public class NormalMD5Digest : MD5DigestBase
	{
		private static readonly ThreadLocal<System.Security.Cryptography.MD5> Hasher = new(System.Security.Cryptography.MD5.Create);

		public override void ComputeHash(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Hasher.Value!.TryComputeHash(origin, destination, out _);
		}
	}
}
