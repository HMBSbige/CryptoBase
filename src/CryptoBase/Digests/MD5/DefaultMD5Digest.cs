namespace CryptoBase.Digests.MD5;

public class DefaultMD5Digest() : DefaultDigest(HashAlgorithmName.MD5)
{
	public override string Name => @"MD5";

	public override int BlockSize => HashConstants.Md5BlockSize;
}
