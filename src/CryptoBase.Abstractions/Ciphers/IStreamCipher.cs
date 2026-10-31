namespace CryptoBase.Abstractions.Ciphers;

/// <summary>
/// Defines a stream cipher.
/// </summary>
public interface IStreamCipher : IDisposable
{
	/// <summary>
	/// XORs <paramref name="source" /> with the keystream and writes the result to <paramref name="destination" />.
	/// </summary>
	/// <remarks>If source and destination overlap, they must start at the same byte.</remarks>
	void Xor(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination);
}
