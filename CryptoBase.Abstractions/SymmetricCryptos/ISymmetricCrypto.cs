namespace CryptoBase.Abstractions.SymmetricCryptos;

public interface ISymmetricCrypto : IDisposable
{
	/// <summary>
	/// 算法名
	/// </summary>
	string Name { get; }
}
