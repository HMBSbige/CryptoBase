namespace CryptoBase.Digests.MD5;

/// <summary>
/// Provides MD5 hashing through the platform cryptography implementation.
/// </summary>
public class DefaultMD5Digest() : DefaultDigest(HashAlgorithmName.MD5)
{
	/// <inheritdoc />
	public override string Name => @"MD5";

	/// <inheritdoc />
	public override int BlockSize => HashConstants.Md5BlockSize;
}
