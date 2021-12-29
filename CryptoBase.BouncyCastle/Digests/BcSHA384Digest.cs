using CryptoBase.Abstractions.Digests;
using Org.BouncyCastle.Crypto.Digests;

namespace CryptoBase.BouncyCastle.Digests;

public class BcSHA384Digest : BcDigest
{
	public override string Name => @"SHA-384";

	public override int Length => HashConstants.Sha384Length;

	public override int BlockSize => HashConstants.Sha384BlockSize;

	public BcSHA384Digest() : base(new Sha384Digest())
	{
	}
}
