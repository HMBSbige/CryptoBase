using System;

namespace CryptoBase.Abstractions.Digests
{
	public abstract class SHA1DigestBase : IHash
	{
		public string Name { get; } = @"SHA-1";
		public const byte Sha1Length = 20;
		public int Length { get; } = Sha1Length;
		public abstract void ComputeHash(in ReadOnlySpan<byte> origin, Span<byte> destination);
	}
}
