using System;

namespace CryptoBase.Abstractions.SymmetricCryptos
{
	public interface ISymmetricCrypto
	{
		string Name { get; }
		void Encrypt(ReadOnlySpan<byte> plain, Span<byte> cipher);
		void Decrypt(ReadOnlySpan<byte> cipher, Span<byte> plain);
		void Reset();
	}
}
