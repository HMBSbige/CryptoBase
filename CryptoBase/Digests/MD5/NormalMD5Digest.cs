using CryptoBase.Abstractions.Digests;
using System;
using System.Threading;

namespace CryptoBase.Digests.MD5
{
	public class NormalMD5Digest : MD5DigestBase
	{
		private static readonly ThreadLocal<System.Security.Cryptography.MD5> Hasher = new(System.Security.Cryptography.MD5.Create);

		public override Span<byte> Compute(in ReadOnlySpan<byte> origin)
		{
			Span<byte> span = new byte[Md5Len];

			Hasher.Value!.TryComputeHash(origin, span, out _);

			return span;
		}
	}
}
