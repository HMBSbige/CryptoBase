using CryptoBase.Abstractions.Digests;
using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.BouncyCastle.Digests
{
	public class BcSM3Digest : BcDigest
	{
		public override string Name => @"SM3";

		public override int Length => HashConstants.SM3Length;

		public BcSM3Digest() : base(new SM3Digest())
		{
		}
	}
}
