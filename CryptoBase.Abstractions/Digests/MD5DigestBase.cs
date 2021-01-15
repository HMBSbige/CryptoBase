using System;

namespace CryptoBase.Abstractions.Digests
{
	public abstract class MD5DigestBase : IHash
	{
		public string Name { get; } = @"MD5";
		public const byte Md5Len = 16;
		public abstract Span<byte> Compute(in ReadOnlySpan<byte> origin);
	}
}
