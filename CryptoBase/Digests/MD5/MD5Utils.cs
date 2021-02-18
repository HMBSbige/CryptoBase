using CryptoBase.Abstractions.Digests;
using System;
using System.Threading;

namespace CryptoBase.Digests.MD5
{
	public static class MD5Utils
	{
		private static readonly ThreadLocal<MD5DigestBase> Normal = new(() => new DefaultMD5Digest());
		private static readonly ThreadLocal<MD5DigestBase> Slow = new(() => new MD5Digest());
		private static readonly ThreadLocal<MD5DigestBase> Fast = new(() => new Fast440MD5Digest());

		public static void Default(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Normal.Value!.ComputeHash(origin, destination);
		}

		public static void MayFast(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Slow.Value!.ComputeHash(origin, destination);
		}

		public static void Fast440(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Fast.Value!.ComputeHash(origin, destination);
		}
	}
}
