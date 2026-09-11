namespace CryptoBase.Abstractions.Macs;

/// <summary>
/// Defines an incremental MAC algorithm with disposable keyed state.
/// </summary>
/// <remarks>Each instance owns its keyed state. Disposal erases it and is idempotent; subsequent instance operations other than disposal throw <see cref="ObjectDisposedException" />.</remarks>
/// <typeparam name="TSelf">The implementing type.</typeparam>
public interface IMacAlgorithm<out TSelf> : IOneShotMacAlgorithm, IDisposable where TSelf : class, IMacAlgorithm<TSelf>
{
	/// <summary>
	/// Creates an instance initialized with <paramref name="key" />.
	/// </summary>
	/// <remarks>On failure, implementation-owned key material and state are erased.</remarks>
	/// <param name="key">The key.</param>
	/// <returns>The initialized instance.</returns>
	/// <exception cref="ArgumentException"><paramref name="key" /> is invalid.</exception>
	static abstract TSelf Create(ReadOnlySpan<byte> key);

	/// <summary>
	/// Appends <paramref name="source" /> to the current message.
	/// </summary>
	/// <param name="source">The data to append.</param>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	void Append(ReadOnlySpan<byte> source);

	/// <summary>
	/// Resets the message while retaining the key.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	void Reset();

	/// <summary>
	/// Writes the current MAC without changing the state.
	/// </summary>
	/// <remarks>On failure, <paramref name="destination" /> and the state remain unchanged.</remarks>
	/// <param name="destination">The output buffer.</param>
	/// <returns>The value of <see cref="IOneShotMacAlgorithm.MacLengthInBytes" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	int GetCurrentMac(Span<byte> destination);

	/// <summary>
	/// Writes the current MAC, then resets the message while retaining the key.
	/// </summary>
	/// <remarks>On failure, <paramref name="destination" /> and the state remain unchanged.</remarks>
	/// <param name="destination">The output buffer.</param>
	/// <returns>The value of <see cref="IOneShotMacAlgorithm.MacLengthInBytes" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	int GetMacAndReset(Span<byte> destination);
}
