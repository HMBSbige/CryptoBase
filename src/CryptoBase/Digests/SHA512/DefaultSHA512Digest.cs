namespace CryptoBase.Digests.SHA512;

/// <summary>
/// Provides SHA-512 hashing through the platform cryptography implementation.
/// </summary>
public class DefaultSHA512Digest() : DefaultDigest(HashAlgorithmName.SHA512)
{
	/// <inheritdoc />
	public override string Name => @"SHA-512";

	/// <inheritdoc />
	public override int BlockSize => HashConstants.Sha512BlockSize;
}
