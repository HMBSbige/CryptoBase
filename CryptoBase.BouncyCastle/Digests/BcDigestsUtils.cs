using CryptoBase.Abstractions.Digests;
using System;
using System.Threading;

namespace CryptoBase.BouncyCastle.Digests
{
	public static class BcDigestsUtils
	{
		private static readonly ThreadLocal<IHash> Md5 = new(() => new BcMD5Digest());
		private static readonly ThreadLocal<IHash> Sha1 = new(() => new BcSHA1Digest());
		private static readonly ThreadLocal<IHash> Sm3 = new(() => new BcSM3Digest());
		private static readonly ThreadLocal<IHash> Sha256 = new(() => new BcSHA256Digest());
		private static readonly ThreadLocal<IHash> Sha384 = new(() => new BcSHA384Digest());
		private static readonly ThreadLocal<IHash> Sha512 = new(() => new BcSHA512Digest());

		public static void MD5(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Md5.Value!.UpdateFinal(origin, destination);
		}

		public static void SHA1(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Sha1.Value!.UpdateFinal(origin, destination);
		}

		public static void SM3(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Sm3.Value!.UpdateFinal(origin, destination);
		}

		public static void SHA256(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Sha256.Value!.UpdateFinal(origin, destination);
		}

		public static void SHA384(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Sha384.Value!.UpdateFinal(origin, destination);
		}

		public static void SHA512(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Sha512.Value!.UpdateFinal(origin, destination);
		}
	}
}
