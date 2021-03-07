using CryptoBase.Abstractions.Digests;
using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.BouncyCastle.Digests
{
	public class BcSHA1Digest : BcDigest
	{
		public override string Name => @"SHA-1";

		public override int Length => HashConstants.Sha1Length;

		public BcSHA1Digest() : base(new Sha1Digest())
		{
		}
	}
}
