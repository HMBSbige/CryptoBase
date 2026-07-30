namespace CryptoBase.Digests.SHA512;

public class DefaultSHA512Digest() : DefaultDigest(HashAlgorithmName.SHA512)
{
	public override string Name => @"SHA-512";

	public override int BlockSize => HashConstants.Sha512BlockSize;
}
