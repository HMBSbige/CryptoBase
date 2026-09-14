namespace CryptoBase.Abstractions.Hashes;

/// <summary>
/// Defines an incremental hash algorithm.
/// </summary>
/// <remarks>Disposal is idempotent.</remarks>
/// <typeparam name="TSelf">The implementing type.</typeparam>
public interface IHashAlgorithm<out TSelf> : IOneShotHashAlgorithm, IDisposable where TSelf : class, IHashAlgorithm<TSelf>
{
	/// <summary>
	/// Creates an initialized instance.
	/// </summary>
	/// <returns>A new initialized instance.</returns>
	static abstract TSelf Create();

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

	/// <summary>
	/// Writes the hash of the current input without changing the state.
	/// </summary>
	/// <remarks>On failure, <paramref name="destination" /> and the state remain unchanged.</remarks>
	/// <param name="destination">The buffer that receives the hash.</param>
	/// <returns>The number of bytes written to <paramref name="destination" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	int GetCurrentHash(Span<byte> destination);

	/// <summary>
	/// Writes the hash of the current input, then resets the state.
	/// </summary>
	/// <remarks>On failure, <paramref name="destination" /> and the state remain unchanged.</remarks>
	/// <param name="destination">The buffer that receives the hash.</param>
	/// <returns>The number of bytes written to <paramref name="destination" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	int GetHashAndReset(Span<byte> destination);
}
