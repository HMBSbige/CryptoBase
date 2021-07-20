using CryptoBase.Abstractions.Digests;
using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.BouncyCastle.Digests
{
	public class BcSHA256Digest : BcDigest
	{
		public override string Name => @"SHA256";

		public override int Length => HashConstants.Sha256Length;

		public BcSHA256Digest() : base(new Sha256Digest())
		{
		}
	}
}
