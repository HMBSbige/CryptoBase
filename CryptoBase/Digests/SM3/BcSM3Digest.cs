using CryptoBase.Abstractions.Digests;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Threading;

namespace CryptoBase.Digests.SM3
{
	public class BcSM3Digest : SM3DigestBase
	{
		private static readonly ThreadLocal<IDigest> Hasher = new(() => new SM3Digest());

		public override void ComputeHash(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Utils.BcComputeHash(Hasher.Value!, Length, origin, destination);
		}
	}
}
