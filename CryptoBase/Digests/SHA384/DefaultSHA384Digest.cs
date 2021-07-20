using CryptoBase.Abstractions.Digests;

namespace CryptoBase.Digests.SHA384
{
	public class DefaultSHA384Digest : DefaultDigest
	{
		public override string Name => @"SHA-384";

		public override int Length => HashConstants.Sha384Length;

		public override int BlockSize => HashConstants.Sha384BlockSize;

		public DefaultSHA384Digest() : base(System.Security.Cryptography.SHA384.Create())
		{
		}
	}
}
