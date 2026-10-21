namespace CryptoBase.Abstractions;

/// <summary>
/// Defines an algorithm that processes its input incrementally.
/// </summary>
public interface IIncrementalAlgorithm
{
	/// <summary>
	/// Appends <paramref name="source" /> to the current input.
	/// </summary>
	/// <param name="source">The data to append.</param>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	void Append(ReadOnlySpan<byte> source);

	/// <summary>
	/// Resets the state, discarding the current input.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	void Reset();
}
