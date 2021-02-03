using System;

namespace CryptoBase.Abstractions.SymmetricCryptos
{
	public abstract class BlockCryptoBase : IBlockCrypto
	{
		public abstract string Name { get; }

		public abstract int BlockSize { get; }

		public virtual void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			if (source.Length < BlockSize)
			{
				throw new ArgumentException(string.Empty, nameof(source));
			}

			if (destination.Length < BlockSize)
			{
				throw new ArgumentException(string.Empty, nameof(destination));
			}
		}

		public virtual void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			if (source.Length < BlockSize)
			{
				throw new ArgumentException(string.Empty, nameof(source));
			}

			if (destination.Length < BlockSize)
			{
				throw new ArgumentException(string.Empty, nameof(destination));
			}
		}

		public virtual void Dispose() { }
	}
}
