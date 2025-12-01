namespace CryptoBase.Abstractions.SymmetricCryptos;

public interface ISymmetricCrypto : IDisposable
{
	/// <summary>
	/// Gets the name of the symmetric crypto algorithm.
	/// </summary>
	string Name { get; }
}
