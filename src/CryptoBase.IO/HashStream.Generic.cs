namespace CryptoBase.IO;

/// <summary>Provides a pass-through stream that appends every byte read from or written to the inner stream to a hash algorithm.</summary>
/// <remarks>See <see cref="AppendStream{TAlgorithm}" /> for the pass-through behavior.</remarks>
/// <typeparam name="TAlgorithm">The hash algorithm.</typeparam>
public sealed class HashStream<TAlgorithm> : AppendStream<TAlgorithm> where TAlgorithm : class, IHashAlgorithm<TAlgorithm>
{
	/// <summary>Wraps <paramref name="inner" /> so that every byte read from or written to it is appended to <paramref name="hasher" />.</summary>
	/// <param name="inner">The stream that data is read from or written to.</param>
	/// <param name="hasher">The hasher that receives the data. This instance takes ownership of it.</param>
	/// <param name="leaveOpen"><see langword="true" /> to leave <paramref name="inner" /> open when this instance is disposed.</param>
	/// <exception cref="ArgumentNullException"><paramref name="inner" /> or <paramref name="hasher" /> is <see langword="null" />.</exception>
	public HashStream(Stream inner, TAlgorithm hasher, bool leaveOpen = false)
		: base(inner, hasher, leaveOpen)
	{
	}

	/// <summary>Writes the hash of the data seen so far without changing the state.</summary>
	/// <param name="destination">The buffer that receives the hash.</param>
	/// <returns>The number of bytes written to <paramref name="destination" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The stream has been disposed.</exception>
	public int GetCurrentHash(Span<byte> destination)
	{
		return Algorithm.GetCurrentHash(destination);
	}

	/// <summary>Writes the hash of the data seen so far, then resets the state.</summary>
	/// <param name="destination">The buffer that receives the hash.</param>
	/// <returns>The number of bytes written to <paramref name="destination" />.</returns>
	/// <exception cref="ArgumentException"><paramref name="destination" /> is too short.</exception>
	/// <exception cref="ObjectDisposedException">The stream has been disposed.</exception>
	public int GetHashAndReset(Span<byte> destination)
	{
		return Algorithm.GetHashAndReset(destination);
	}
}
