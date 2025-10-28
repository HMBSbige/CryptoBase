namespace CryptoBase.Digests.SHA1;

public class DefaultSHA1Digest : DefaultDigest
{
	public override string Name => @"SHA-1";

	public override int BlockSize => HashConstants.Sha1BlockSize;

	public DefaultSHA1Digest() : base(HashAlgorithmName.SHA1)
	{
	}
}
