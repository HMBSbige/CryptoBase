namespace CryptoBase.Digests.SHA384;

public class DefaultSHA384Digest() : DefaultDigest(HashAlgorithmName.SHA384)
{
	public override string Name => @"SHA-384";

	public override int BlockSize => HashConstants.Sha384BlockSize;
}
