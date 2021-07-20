using CryptoBase.Abstractions.Digests;
using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.BouncyCastle.Digests
{
	public class BcSHA256Digest : BcDigest
	{
		public override string Name => @"SHA-256";

		public override int Length => HashConstants.Sha256Length;

		public override int BlockSize => HashConstants.Sha256BlockSize;

		public BcSHA256Digest() : base(new Sha256Digest())
		{
		}
	}
}
