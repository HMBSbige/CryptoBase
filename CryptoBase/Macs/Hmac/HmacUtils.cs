using CryptoBase.Abstractions;
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
		public static IMac Create(HmacType type, ReadOnlySpan<byte> key)
		{
			return type switch
			{
				HmacType.Sm3 => new HmacSF(key, new SM3Digest()),
				HmacType.Md5 => new HmacSF(key, new DefaultMD5Digest()),
				HmacType.Sha1 => new HmacSF(key, new DefaultSHA1Digest()),
				HmacType.Sha256 => new HmacSF(key, new DefaultSHA256Digest()),
				HmacType.Sha384 => new HmacSF(key, new DefaultSHA384Digest()),
				HmacType.Sha512 => new HmacSF(key, new DefaultSHA512Digest()),
				_ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
			};
		}
	}
}
