namespace CryptoBase.Abstractions.SymmetricCryptos;

/// <summary>
/// Defines stateful stream encryption and decryption.
/// </summary>
public interface IStreamCrypto : ISymmetricCrypto, ICanReset
{
	/// <summary>
	/// Encrypts or decrypts data and advances the cipher state.
	/// </summary>
	/// <param name="source">The input data.</param>
	/// <param name="destination">The output destination.</param>
	void Update(ReadOnlySpan<byte> source, Span<byte> destination);
}
