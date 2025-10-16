using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.BouncyCastle.Digests;

public sealed class BcSHA256Digest() : BcDigest(new Sha256Digest())
{
	public override string Name => @"SHA-256";
}
