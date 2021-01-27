using CryptoBase.Abstractions.Digests;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System;

namespace CryptoBase.BouncyCastle.Digests
{
	public class BcMD5Digest : MD5DigestBase
	{
		private readonly IDigest _hasher = new MD5Digest();

		public override void ComputeHash(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			_hasher.BcComputeHash(Length, origin, destination);
		}
	}
}
