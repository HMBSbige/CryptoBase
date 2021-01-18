using System;

namespace CryptoBase.Abstractions.Digests
{
	public abstract class SM3DigestBase : IHash
	{
		public string Name { get; } = @"SM3";
		public const byte Sm3Length = 32;
		public int Length { get; } = Sm3Length;
		public abstract void ComputeHash(in ReadOnlySpan<byte> origin, Span<byte> destination);
	}
}
