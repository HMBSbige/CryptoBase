using System;

namespace CryptoBase.Abstractions.SymmetricCryptos
{
	public abstract class BlockCryptoBase : IBlockCrypto
	{
		public abstract string Name { get; }

		public abstract bool IsEncrypt { get; init; }

		public abstract int BlockSize { get; }

		public abstract void Update(ReadOnlySpan<byte> source, Span<byte> destination);

		public abstract void Reset();

		public virtual void Dispose() { }
	}
}
