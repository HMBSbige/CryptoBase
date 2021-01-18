using System;

namespace CryptoBase.Abstractions.Digests
{
	public abstract class MD5DigestBase : IHash
	{
		public string Name { get; } = @"MD5";
		public const byte Md5Len = 16;
		public int Length { get; } = Md5Len;
		public abstract void Compute(in ReadOnlySpan<byte> origin, Span<byte> destination);
	}
}
