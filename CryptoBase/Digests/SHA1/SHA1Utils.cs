using CryptoBase.Abstractions.Digests;
using System;
using System.Threading;

namespace CryptoBase.Digests.SHA1
{
	public static class SHA1Utils
	{
		private static readonly ThreadLocal<SHA1DigestBase> Normal = new(() => new NormalSHA1Digest());
		private static readonly ThreadLocal<SHA1DigestBase> Bc = new(() => new BcSHA1Digest());

		public static void Default(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Normal.Value!.ComputeHash(origin, destination);
		}

		public static void BouncyCastle(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Bc.Value!.ComputeHash(origin, destination);
		}
	}
}
