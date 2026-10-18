namespace CryptoBase.IO;

/// <summary>
/// Creates <see cref="DataUnitStream{TCipher}" /> instances.
/// </summary>
public static class DataUnitStream
{
	/// <summary>
	/// Creates a data-unit stream over a seekable stream.
	/// </summary>
	/// <typeparam name="TCipher">The data-unit cipher.</typeparam>
	/// <param name="inner">The seekable stream that stores the ciphertext.</param>
	/// <param name="cipher">The cipher; the returned stream takes ownership of it.</param>
	/// <param name="dataUnitSize">The data unit size, in bytes; at least 16.</param>
	/// <param name="firstDataUnitNumber">The data unit number of the data unit at offset zero.</param>
	/// <param name="leaveOpen"><see langword="true" /> to leave <paramref name="inner" /> open on disposal.</param>
	/// <returns>The data-unit stream.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="inner" /> or <paramref name="cipher" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><paramref name="inner" /> is not seekable or its length is not a multiple of <paramref name="dataUnitSize" />, or <typeparamref name="TCipher" /> does not use a 16-byte tweak.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="dataUnitSize" /> is less than 16.</exception>
	public static DataUnitStream<TCipher> Create<TCipher>(Stream inner, TCipher cipher, int dataUnitSize, UInt128 firstDataUnitNumber = default, bool leaveOpen = false) where TCipher : class, IDataUnitCipher<TCipher>
	{
		return new DataUnitStream<TCipher>(inner, cipher, dataUnitSize, firstDataUnitNumber, leaveOpen);
	}
}
