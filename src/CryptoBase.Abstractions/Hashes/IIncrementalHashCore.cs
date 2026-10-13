namespace CryptoBase.Abstractions.Hashes;

/// <summary>
/// Defines the mutable core of an incremental hash algorithm.
/// </summary>
public interface IIncrementalHashCore
{
	/// <summary>
	/// Gets the hash length, in bytes.
	/// </summary>
	static abstract int HashLength { get; }

	/// <summary>
	/// Appends <paramref name="source" /> to the current input.
	/// </summary>
	/// <remarks>Must not fail.</remarks>
	/// <param name="source">The data to append.</param>
	void Append(ReadOnlySpan<byte> source);

	/// <summary>
	/// Writes the hash of the current input to the first <see cref="HashLength" /> bytes of <paramref name="destination" />.
	/// </summary>
	/// <remarks>Must fail only when <paramref name="destination" /> is too short, and then leave the core and <paramref name="destination" /> unchanged.</remarks>
	/// <param name="destination">The buffer that receives the hash.</param>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	void Finalize(Span<byte> destination);
}
