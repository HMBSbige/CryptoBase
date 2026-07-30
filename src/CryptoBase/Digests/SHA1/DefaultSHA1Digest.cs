namespace CryptoBase.Digests.SHA1;

public class DefaultSHA1Digest() : DefaultDigest(HashAlgorithmName.SHA1)
{
	public override string Name => @"SHA-1";

	public override int BlockSize => HashConstants.Sha1BlockSize;
}
