using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.BouncyCastle.Digests;

public sealed class BcSHA384Digest() : BcDigest(new Sha384Digest())
{
	public override string Name => @"SHA-384";
}
