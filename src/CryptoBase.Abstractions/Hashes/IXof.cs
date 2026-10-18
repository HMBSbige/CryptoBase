namespace CryptoBase.Abstractions.Hashes;

/// <summary>
/// Defines an extendable-output function (XOF), whose output is a stream of any length.
/// </summary>
/// <remarks>
/// <para>
/// A shorter output is a prefix of every longer one. The first nonempty <see cref="Read" /> ends the input and moves the instance to the reading state,
/// in which it returns successive bytes of the output stream; <see cref="Append" />, <see cref="GetCurrentHash" /> and <see cref="GetHashAndReset" />
/// then throw <see cref="InvalidOperationException" /> until <see cref="Reset" />.
/// </para>
/// <para>Disposal is idempotent; subsequent operations other than disposal throw <see cref="ObjectDisposedException" />.</para>
/// </remarks>
/// <typeparam name="TSelf">The implementing type.</typeparam>
public interface IXof<out TSelf> : IDisposable where TSelf : class, IXof<TSelf>
{
	/// <summary>
	/// Creates an initialized instance.
	/// </summary>
	/// <returns>A new initialized instance.</returns>
	static abstract TSelf Create();

	/// <summary>
	/// Computes the output for <paramref name="source" />.
	/// </summary>
	/// <param name="source">The data to hash.</param>
	/// <param name="destination">The buffer that receives the output; its length selects the output length.</param>
	static abstract void HashData(ReadOnlySpan<byte> source, Span<byte> destination);

	/// <summary>
	/// Appends <paramref name="source" /> to the current input.
	/// </summary>
	/// <param name="source">The data to append.</param>
	/// <exception cref="InvalidOperationException">The instance is reading; call <see cref="Reset" /> first.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	void Append(ReadOnlySpan<byte> source);

	/// <summary>
	/// Writes the next <c>destination.Length</c> bytes of the output stream for the current input.
	/// </summary>
	/// <remarks>
	/// The first nonempty read ends the input and starts the reading state at the beginning of the stream; each later read continues where the previous
	/// one stopped. An empty <paramref name="destination" /> leaves the state unchanged.
	/// </remarks>
	/// <param name="destination">The buffer that receives the output.</param>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	void Read(Span<byte> destination);

	/// <summary>
	/// Writes the start of the output stream for the current input without changing the state.
	/// </summary>
	/// <param name="destination">The buffer that receives the output; its length selects the output length.</param>
	/// <exception cref="InvalidOperationException">The instance is reading; call <see cref="Reset" /> first.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	void GetCurrentHash(Span<byte> destination);

	/// <summary>
	/// Writes the start of the output stream for the current input, then resets the state.
	/// </summary>
	/// <param name="destination">The buffer that receives the output; its length selects the output length.</param>
	/// <exception cref="InvalidOperationException">The instance is reading; call <see cref="Reset" /> first.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	void GetHashAndReset(Span<byte> destination);

	/// <summary>
	/// Resets the state, discarding the current input and leaving the reading state.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	void Reset();
}
