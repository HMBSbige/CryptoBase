using System.Security.Cryptography;

namespace CryptoBase.Digests.SHA384;

public class DefaultSHA384Digest : DefaultDigest
{
	public override string Name => @"SHA-384";

	public override int BlockSize => HashConstants.Sha384BlockSize;

	public DefaultSHA384Digest() : base(HashAlgorithmName.SHA384)
	{
	}
}
