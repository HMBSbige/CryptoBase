using System;

namespace CryptoBase.Abstractions.SymmetricCryptos
{
	public abstract class StreamCryptoBase : ISymmetricCrypto
	{
		public abstract string Name { get; }

		protected abstract void Update(ReadOnlySpan<byte> source, Span<byte> destination);

		public void Encrypt(ReadOnlySpan<byte> plain, Span<byte> cipher)
		{
			Update(plain, cipher);
		}

		public void Decrypt(ReadOnlySpan<byte> cipher, Span<byte> plain)
		{
			Update(cipher, plain);
		}

		public abstract void Reset();

		public virtual void Dispose() { }
	}
}
