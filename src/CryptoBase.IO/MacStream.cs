namespace CryptoBase.IO;

/// <summary>Creates <see cref="MacStream{TAlgorithm}" /> instances with the algorithm type inferred from the MAC algorithm.</summary>
public static class MacStream
{
	/// <summary>Wraps <paramref name="inner" /> so that every byte read from or written to it is appended to <paramref name="mac" />.</summary>
	/// <typeparam name="TAlgorithm">The MAC algorithm.</typeparam>
	/// <param name="inner">The stream that data is read from or written to.</param>
	/// <param name="mac">The keyed MAC algorithm that receives the data. The returned stream takes ownership of it.</param>
	/// <param name="leaveOpen"><see langword="true" /> to leave <paramref name="inner" /> open when the returned stream is disposed.</param>
	/// <returns>A pass-through stream that authenticates the data flowing through it.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="inner" /> or <paramref name="mac" /> is <see langword="null" />.</exception>
	public static MacStream<TAlgorithm> Create<TAlgorithm>(Stream inner, TAlgorithm mac, bool leaveOpen = false) where TAlgorithm : class, IMacAlgorithm<TAlgorithm>
	{
		return new MacStream<TAlgorithm>(inner, mac, leaveOpen);
	}
}
