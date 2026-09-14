namespace CryptoBase.Abstractions.Hashes;

/// <summary>
/// Defines a one-shot hash algorithm.
/// </summary>
public interface IOneShotHashAlgorithm
{
	/// <summary>
	/// Gets the hash length, in bytes.
	/// </summary>
	static abstract int HashLength { get; }

	/// <summary>
	/// Computes the hash of <paramref name="source" />.
	/// </summary>
	/// <remarks>On failure, <paramref name="destination" /> remains unchanged.</remarks>
	/// <param name="source">The data to hash.</param>
	/// <param name="destination">The output buffer.</param>
	/// <returns>The value of <see cref="HashLength" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	static abstract int HashData(ReadOnlySpan<byte> source, Span<byte> destination);
}
