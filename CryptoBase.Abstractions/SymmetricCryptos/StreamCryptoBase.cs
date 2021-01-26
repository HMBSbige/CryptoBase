using System;

namespace CryptoBase.Abstractions.SymmetricCryptos
{
	public abstract class StreamCryptoBase : ISymmetricCrypto
	{
		public abstract string Name { get; }

		protected abstract void Update(ReadOnlySpan<byte> source, Span<byte> destination);

		public void Encrypt(ReadOnlySpan<byte> plain, Span<byte> cipher)
		{
			if (cipher.Length < plain.Length)
			{
				throw new ArgumentException(string.Empty, nameof(cipher));
			}
			Update(plain, cipher);
		}

		public void Decrypt(ReadOnlySpan<byte> cipher, Span<byte> plain)
		{
			if (plain.Length < cipher.Length)
			{
				throw new ArgumentException(string.Empty, nameof(plain));
			}
			Update(cipher, plain);
		}

		public abstract void Reset();

		public virtual void Dispose() { }
	}
}
