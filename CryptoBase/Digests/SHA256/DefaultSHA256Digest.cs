using CryptoBase.Abstractions.Digests;

namespace CryptoBase.Digests.SHA256
{
	public class DefaultSHA256Digest : DefaultDigest
	{
		public override string Name => @"SHA256";

		public override int Length => HashConstants.Sha256Length;

		public DefaultSHA256Digest() : base(System.Security.Cryptography.SHA256.Create())
		{
		}
	}
}
