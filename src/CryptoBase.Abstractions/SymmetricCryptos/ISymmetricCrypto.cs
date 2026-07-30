namespace CryptoBase.Abstractions.SymmetricCryptos;

/// <summary>
/// Defines a symmetric cryptographic algorithm.
/// </summary>
public interface ISymmetricCrypto : IDisposable
{
	/// <summary>
	/// Gets the name of the symmetric crypto algorithm.
	/// </summary>
	string Name { get; }
}
