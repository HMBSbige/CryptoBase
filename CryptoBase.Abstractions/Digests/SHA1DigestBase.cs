using System;

namespace CryptoBase.Abstractions.Digests
{
	public abstract class SHA1DigestBase : IHash
	{
		public string Name => @"SHA-1";
		public const byte Sha1Length = 20;
		public int Length => Sha1Length;
		public abstract void ComputeHash(in ReadOnlySpan<byte> origin, Span<byte> destination);
	}
}
