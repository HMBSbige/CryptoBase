using System;

namespace CryptoBase.Abstractions.SymmetricCryptos
{
	public interface ISymmetricCrypto : IDisposable
	{
		/// <summary>
		/// 算法名
		/// </summary>
		string Name { get; }

		/// <summary>
		/// 加密
		/// </summary>
		void Encrypt(ReadOnlySpan<byte> plain, Span<byte> cipher);

		/// <summary>
		/// 解密
		/// </summary>
		void Decrypt(ReadOnlySpan<byte> cipher, Span<byte> plain);

		/// <summary>
		/// 重置状态
		/// </summary>
		void Reset();
	}
}
