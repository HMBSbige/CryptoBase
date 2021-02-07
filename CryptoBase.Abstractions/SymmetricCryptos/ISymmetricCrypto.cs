using System;

namespace CryptoBase.Abstractions.SymmetricCryptos
{
	public interface ISymmetricCrypto : ICanReset, IDisposable
	{
		/// <summary>
		/// 算法名
		/// </summary>
		string Name { get; }
	}
}
