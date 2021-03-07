using CryptoBase.Abstractions.Digests;

namespace CryptoBase.Digests.MD5
{
	public class DefaultMD5Digest : DefaultDigest
	{
		public override string Name => @"MD5";

		public override int Length => HashConstants.Md5Length;

		public DefaultMD5Digest() : base(System.Security.Cryptography.MD5.Create())
		{
		}
	}
}
