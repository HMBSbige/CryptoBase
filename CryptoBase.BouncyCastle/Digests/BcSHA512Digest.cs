using CryptoBase.Abstractions.Digests;
using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.BouncyCastle.Digests
{
	public class BcSHA512Digest : BcDigest
	{
		public override string Name => @"SHA-512";

		public override int Length => HashConstants.Sha512Length;

		public override int BlockSize => HashConstants.Sha512BlockSize;

		public BcSHA512Digest() : base(new Sha512Digest())
		{
		}
	}
}
