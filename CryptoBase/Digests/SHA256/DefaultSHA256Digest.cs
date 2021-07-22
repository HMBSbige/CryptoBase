using CryptoBase.Abstractions.Digests;
using System.Security.Cryptography;

namespace CryptoBase.Digests.SHA256
{
	public class DefaultSHA256Digest : DefaultDigest
	{
		public override string Name => @"SHA-256";

		public override int BlockSize => HashConstants.Sha256BlockSize;

		public DefaultSHA256Digest() : base(HashAlgorithmName.SHA256)
		{
		}
	}
}
