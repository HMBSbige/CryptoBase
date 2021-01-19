using CryptoBase.Abstractions.Digests;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System;

namespace CryptoBase.Digests.SHA1
{
	public class BcSHA1Digest : SHA1DigestBase
	{
		private readonly IDigest _hasher = new Sha1Digest();

		public override void ComputeHash(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Utils.BcComputeHash(_hasher, Length, origin, destination);
		}
	}
}
