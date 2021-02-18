using CryptoBase.Abstractions.Digests;
using System;
using System.Threading;

namespace CryptoBase.Digests.SHA1
{
	public static class SHA1Utils
	{
		private static readonly ThreadLocal<SHA1DigestBase> Normal = new(() => new DefaultSHA1Digest());

		public static void Default(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Normal.Value!.ComputeHash(origin, destination);
		}
	}
}
