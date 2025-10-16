using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.BouncyCastle.Digests;

public sealed class BcMD5Digest() : BcDigest(new MD5Digest())
{
	public override string Name => @"MD5";
}
