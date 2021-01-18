using CryptoBase.Abstractions.Digests;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Threading;

namespace CryptoBase.Digests.SHA1
{
	public class BcSHA1Digest : SHA1DigestBase
	{
		private static readonly ThreadLocal<Sha1Digest> Hasher = new(() => new Sha1Digest());

		public override void ComputeHash(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Utils.BcComputeHash(Hasher.Value!, Length, origin, destination);
		}
	}
}
