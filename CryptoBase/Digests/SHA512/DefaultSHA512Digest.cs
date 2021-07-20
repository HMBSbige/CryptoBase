using CryptoBase.Abstractions.Digests;

namespace CryptoBase.Digests.SHA512
{
	public class DefaultSHA512Digest : DefaultDigest
	{
		public override string Name => @"SHA512";

		public override int Length => HashConstants.Sha512Length;

		public DefaultSHA512Digest() : base(System.Security.Cryptography.SHA512.Create())
		{
		}
	}
}
