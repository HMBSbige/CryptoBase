namespace CryptoBase.Digests.SHA256;

public class DefaultSHA256Digest() : DefaultDigest(HashAlgorithmName.SHA256)
{
	public override string Name => @"SHA-256";

	public override int BlockSize => HashConstants.Sha256BlockSize;
}
