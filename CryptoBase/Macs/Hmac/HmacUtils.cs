using CryptoBase.Abstractions;
using CryptoBase.Abstractions.Digests;
using CryptoBase.Digests;
using CryptoBase.Digests.MD5;
using CryptoBase.Digests.SHA1;
using CryptoBase.Digests.SHA256;
using CryptoBase.Digests.SHA384;
using CryptoBase.Digests.SHA512;
using CryptoBase.Digests.SM3;
using System;

namespace CryptoBase.Macs.Hmac
{
	public static class HmacUtils
	{
		public static IMac Create(ReadOnlySpan<byte> key, IHash hash)
		{
			return new HmacSF(key, hash);
		}

		public static IMac Create(DigestType type, ReadOnlySpan<byte> key)
		{
			return type switch
			{
				DigestType.Sm3 => Create(key, new SM3Digest()),
				DigestType.Md5 => Create(key, new DefaultMD5Digest()),
				DigestType.Sha1 => Create(key, new DefaultSHA1Digest()),
				DigestType.Sha256 => Create(key, new DefaultSHA256Digest()),
				DigestType.Sha384 => Create(key, new DefaultSHA384Digest()),
				DigestType.Sha512 => Create(key, new DefaultSHA512Digest()),
				_ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
			};
		}
	}
}
