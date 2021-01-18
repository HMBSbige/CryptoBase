using CryptoBase.Abstractions.Digests;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using System;
using System.Threading;

namespace CryptoBase.Digests.MD5
{
	public class BcMD5Digest : MD5DigestBase
	{
		private static readonly ThreadLocal<IDigest> Hasher = new(() => new MD5Digest());

		public override void ComputeHash(in ReadOnlySpan<byte> origin, Span<byte> destination)
		{
			Utils.BcComputeHash(Hasher.Value!, Length, origin, destination);
		}
	}
}
