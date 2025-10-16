using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.BouncyCastle.Digests;

public sealed class BcSHA1Digest() : BcDigest(new Sha1Digest())
{
	public override string Name => @"SHA-1";
}
