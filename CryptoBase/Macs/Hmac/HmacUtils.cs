using CryptoBase.Abstractions;
using CryptoBase.Abstractions.Digests;
using CryptoBase.Digests;
using CryptoBase.Digests.SM3;
using System;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace CryptoBase.Macs.Hmac
{
	public static class HmacUtils
	{
		public static IMac Create(ReadOnlySpan<byte> key, IHash hash)
		{
			return new HmacSF(key, hash);
		}

		public static IMac Create(ReadOnlySpan<byte> key, HashAlgorithmName name)
		{
			return new DefaultHmac(key, name);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static IMac Create(DigestType type, ReadOnlySpan<byte> key)
		{
			return type switch
			{
				DigestType.Sm3 => Create(key, new SM3Digest()),
				DigestType.Md5 => Create(key, HashAlgorithmName.MD5),
				DigestType.Sha1 => Create(key, HashAlgorithmName.SHA1),
				DigestType.Sha256 => Create(key, HashAlgorithmName.SHA256),
				DigestType.Sha384 => Create(key, HashAlgorithmName.SHA384),
				DigestType.Sha512 => Create(key, HashAlgorithmName.SHA512),
				_ => throw new ArgumentOutOfRangeException(nameof(type), type, null)
			};
		}
	}
}
