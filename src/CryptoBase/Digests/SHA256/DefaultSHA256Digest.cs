namespace CryptoBase.Digests.SHA256;

/// <summary>
/// Provides SHA-256 hashing through the platform cryptography implementation.
/// </summary>
public class DefaultSHA256Digest() : DefaultDigest(HashAlgorithmName.SHA256)
{
	/// <inheritdoc />
	public override string Name => @"SHA-256";

	/// <inheritdoc />
	public override int BlockSize => HashConstants.Sha256BlockSize;
}
