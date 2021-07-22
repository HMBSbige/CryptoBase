using CryptoBase.Abstractions.Digests;
using CryptoBase.Digests.MD5;
using CryptoBase.Digests.SHA1;
using CryptoBase.Digests.SHA256;
using CryptoBase.Digests.SHA384;
using CryptoBase.Digests.SHA512;
using CryptoBase.Digests.SM3;
using System;
using System.Runtime.CompilerServices;

namespace CryptoBase.Digests
{
	public static class DigestUtils
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static IHash Create(DigestType type)
		{
			return type switch
			{
				DigestType.Sm3 => new SM3Digest(),
				DigestType.Md5 => new DefaultMD5Digest(),
				DigestType.Sha1 => new DefaultSHA1Digest(),
				DigestType.Sha256 => new DefaultSHA256Digest(),
				DigestType.Sha384 => new DefaultSHA384Digest(),
				DigestType.Sha512 => new DefaultSHA512Digest(),
				_ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
			};
		}
	}
}
