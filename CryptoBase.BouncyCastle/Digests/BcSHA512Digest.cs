using CryptoBase.Abstractions.Digests;
using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.BouncyCastle.Digests
{
	public class BcSHA512Digest : BcDigest
	{
		public override string Name => @"SHA512";

		public override int Length => HashConstants.Sha512Length;

		public BcSHA512Digest() : base(new Sha512Digest())
		{
		}
	}
}
