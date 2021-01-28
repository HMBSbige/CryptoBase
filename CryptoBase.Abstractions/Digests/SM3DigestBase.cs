using System;

namespace CryptoBase.Abstractions.Digests
{
	public abstract class SM3DigestBase : IHash
	{
		public string Name => @"SM3";
		public const byte SM3Length = 32;
		public int Length => SM3Length;
		public abstract void ComputeHash(in ReadOnlySpan<byte> origin, Span<byte> destination);
	}
}
