using CryptoBase.Abstractions.Digests;
using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.BouncyCastle.Digests
{
	public class BcMD5Digest : BcDigest
	{
		public override string Name => @"MD5";

		public override int Length => HashConstants.Md5Length;

		public override int BlockSize => HashConstants.Md5BlockSize;

		public BcMD5Digest() : base(new MD5Digest())
		{
		}
	}
}
