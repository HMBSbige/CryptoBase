using CryptoBase.Abstractions.Digests;
using System;
using System.Threading;

namespace CryptoBase.BouncyCastle.Digests
{
	public static class BcDigestsUtils
	{
		private static readonly ThreadLocal<MD5DigestBase> Md5 = new(() => new BcMD5Digest());
		private static readonly ThreadLocal<SHA1DigestBase> Sha1 = new(() => new BcSHA1Digest());
		private static readonly ThreadLocal<SM3DigestBase> Sm3 = new(() => new BcSM3Digest());

		public static void MD5(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Md5.Value!.ComputeHash(origin, destination);
		}

		public static void SHA1(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Sha1.Value!.ComputeHash(origin, destination);
		}

		public static void SM3(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Sm3.Value!.ComputeHash(origin, destination);
		}
	}
}
