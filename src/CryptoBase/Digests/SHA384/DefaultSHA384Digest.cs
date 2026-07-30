namespace CryptoBase.Digests.SHA384;

/// <summary>
/// Provides SHA-384 hashing through the platform cryptography implementation.
/// </summary>
public class DefaultSHA384Digest() : DefaultDigest(HashAlgorithmName.SHA384)
{
	/// <inheritdoc />
	public override string Name => @"SHA-384";

	/// <inheritdoc />
	public override int BlockSize => HashConstants.Sha384BlockSize;
}
