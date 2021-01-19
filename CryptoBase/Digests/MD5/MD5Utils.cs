using CryptoBase.Abstractions.Digests;
using System;
using System.Threading;

namespace CryptoBase.Digests.MD5
{
	public static class MD5Utils
	{
		private static readonly ThreadLocal<MD5DigestBase> Normal = new(() => new NormalMD5Digest());
		private static readonly ThreadLocal<MD5DigestBase> Bc = new(() => new BcMD5Digest());
		private static readonly ThreadLocal<MD5DigestBase> Slow = new(() => new SlowMD5Digest());

		public static void Default(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Normal.Value!.ComputeHash(origin, destination);
		}

		public static void BouncyCastle(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Bc.Value!.ComputeHash(origin, destination);
		}

		public static void MayFast(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Slow.Value!.ComputeHash(origin, destination);
		}
	}
}
