namespace CryptoBase.Abstractions.Digests;

/// <summary>
/// Represents an incremental hash algorithm.
/// </summary>
public interface IHash : ICanReset, IDisposable
{
	/// <summary>
	/// Gets the algorithm name.
	/// </summary>
	string Name { get; }

	/// <summary>
	/// Gets the hash length, in bytes.
	/// </summary>
	int Length { get; }

	/// <summary>
	/// Gets the block size, in bytes.
	/// </summary>
	int BlockSize { get; }

	/// <summary>
	/// Appends data, writes the hash, and resets the state.
	/// </summary>
	void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination);

	/// <summary>
	/// Appends data to the current hash computation.
	/// </summary>
	void Update(ReadOnlySpan<byte> source);

	/// <summary>
	/// Writes the hash of the accumulated data and resets the state.
	/// </summary>
	void GetHash(Span<byte> destination);
}
