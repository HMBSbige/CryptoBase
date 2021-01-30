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
		/// 重置状态
		/// </summary>
		void Reset();

		/// <summary>
		/// 加密/解密
		/// </summary>
		void Update(ReadOnlySpan<byte> source, Span<byte> destination);
	}
}
