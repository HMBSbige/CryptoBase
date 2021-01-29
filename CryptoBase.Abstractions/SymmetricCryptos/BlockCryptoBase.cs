using System;

namespace CryptoBase.Abstractions.SymmetricCryptos
{
	public abstract class BlockCryptoBase : ISymmetricCrypto, IBlockCrypto
	{
		public abstract string Name { get; }

		public abstract bool IsEncrypt { get; init; }

		public abstract int BlockSize { get; }

		public abstract void UpdateBlock(ReadOnlySpan<byte> source, Span<byte> destination);

		public virtual void Encrypt(ReadOnlySpan<byte> plain, Span<byte> cipher)
		{
			if (!IsEncrypt)
			{
				throw new InvalidOperationException();
			}

			UpdateBlock(plain, cipher);
		}

		public virtual void Decrypt(ReadOnlySpan<byte> cipher, Span<byte> plain)
		{
			if (IsEncrypt)
			{
				throw new InvalidOperationException();
			}

			UpdateBlock(cipher, plain);
		}

		public abstract void Reset();

		public virtual void Dispose() { }
	}
}
