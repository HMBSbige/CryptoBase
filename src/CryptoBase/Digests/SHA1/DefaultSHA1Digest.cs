namespace CryptoBase.Digests.SHA1;

/// <summary>
/// Provides SHA-1 hashing through the platform cryptography implementation.
/// </summary>
public class DefaultSHA1Digest() : DefaultDigest(HashAlgorithmName.SHA1)
{
	/// <inheritdoc />
	public override string Name => @"SHA-1";

	/// <inheritdoc />
	public override int BlockSize => HashConstants.Sha1BlockSize;
}
