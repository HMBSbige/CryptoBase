using System.Security.Cryptography;

namespace CryptoBase.Digests.MD5;

public class DefaultMD5Digest : DefaultDigest
{
	public override string Name => @"MD5";

	public override int BlockSize => HashConstants.Md5BlockSize;

	public DefaultMD5Digest() : base(HashAlgorithmName.MD5)
	{
	}
}
