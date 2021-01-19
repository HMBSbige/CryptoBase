using CryptoBase.Abstractions.Digests;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System;

namespace CryptoBase.Digests.SM3
{
	public class BcSM3Digest : SM3DigestBase
	{
		private readonly IDigest _hasher = new SM3Digest();

		public override void ComputeHash(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Utils.BcComputeHash(_hasher, Length, origin, destination);
		}
	}
}
