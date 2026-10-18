namespace CryptoBase.Abstractions.Hashes;

/// <summary>
/// Defines the mutable core of an extendable-output function (XOF).
/// </summary>
/// <remarks>
/// The core need not check the order of calls: callers must not append after the first read.
/// <see cref="IXof{TSelf}" /> implementations enforce that order.
/// </remarks>
/// <typeparam name="TSelf">The implementing core type.</typeparam>
public interface IXofCore<out TSelf> where TSelf : unmanaged, IXofCore<TSelf>
{
	/// <summary>
	/// Creates an initialized core.
	/// </summary>
	/// <remarks>Must not fail.</remarks>
	/// <returns>The initialized core.</returns>
	static abstract TSelf Create();

	/// <summary>
	/// Appends <paramref name="source" /> to the current input.
	/// </summary>
	/// <remarks>Must not fail, and must not be called after <see cref="Read" />.</remarks>
	/// <param name="source">The data to append.</param>
	void Append(ReadOnlySpan<byte> source);

	/// <summary>
	/// Writes the next <c>destination.Length</c> bytes of the output stream.
	/// </summary>
	/// <remarks>
	/// The first call ends the input, even with an empty <paramref name="destination" />; later calls continue the stream where the previous one stopped.
	/// Must not fail.
	/// </remarks>
	/// <param name="destination">The buffer that receives the output.</param>
	void Read(Span<byte> destination);
}
