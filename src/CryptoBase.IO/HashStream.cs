namespace CryptoBase.IO;

/// <summary>Creates <see cref="HashStream{TAlgorithm}" /> instances with the algorithm type inferred from the hasher.</summary>
public static class HashStream
{
	/// <summary>Wraps <paramref name="inner" /> so that every byte read from or written to it is appended to <paramref name="hasher" />.</summary>
	/// <typeparam name="TAlgorithm">The hash algorithm.</typeparam>
	/// <param name="inner">The stream that data is read from or written to.</param>
	/// <param name="hasher">The hasher that receives the data. The returned stream takes ownership of it.</param>
	/// <param name="leaveOpen"><see langword="true" /> to leave <paramref name="inner" /> open when the returned stream is disposed.</param>
	/// <returns>A pass-through stream that hashes the data flowing through it.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="inner" /> or <paramref name="hasher" /> is <see langword="null" />.</exception>
	public static HashStream<TAlgorithm> Create<TAlgorithm>(Stream inner, TAlgorithm hasher, bool leaveOpen = false) where TAlgorithm : class, IHashAlgorithm<TAlgorithm>
	{
		return new HashStream<TAlgorithm>(inner, hasher, leaveOpen);
	}
}
