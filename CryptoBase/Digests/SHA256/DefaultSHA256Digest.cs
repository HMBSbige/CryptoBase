using CryptoBase.Abstractions.Digests;

namespace CryptoBase.Digests.SHA256
{
	public class DefaultSHA256Digest : DefaultDigest
	{
		public override string Name => @"SHA-256";

		public override int Length => HashConstants.Sha256Length;

		public override int BlockSize => HashConstants.Sha256BlockSize;

		public DefaultSHA256Digest() : base(System.Security.Cryptography.SHA256.Create())
		{
		}
	}
}
