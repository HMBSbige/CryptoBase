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
	/// <param name="source">The data to append.</param>
	void Append(ReadOnlySpan<byte> source);

	/// <summary>
	/// Finalizes the current input into <paramref name="destination" />.
	/// </summary>
	/// <param name="destination">The output buffer, at least <see cref="HashLength" /> bytes long.</param>
	void Finalize(Span<byte> destination);
}
