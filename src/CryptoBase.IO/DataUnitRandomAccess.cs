namespace CryptoBase.IO;

/// <summary>
/// Creates <see cref="DataUnitRandomAccess{TCipher}" /> instances.
/// </summary>
public static class DataUnitRandomAccess
{
	/// <summary>
	/// Creates positional data-unit access over a file handle.
	/// </summary>
	/// <typeparam name="TCipher">The data-unit cipher.</typeparam>
	/// <param name="handle">The file handle that stores the ciphertext.</param>
	/// <param name="cipher">The cipher; the returned instance takes ownership of it.</param>
	/// <param name="dataUnitSize">The data unit size, in bytes; at least 16.</param>
	/// <param name="firstDataUnitNumber">The data unit number of the data unit at offset zero.</param>
	/// <param name="leaveOpen"><see langword="true" /> to leave <paramref name="handle" /> open on disposal.</param>
	/// <returns>The positional data-unit access.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="handle" /> or <paramref name="cipher" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentException"><typeparamref name="TCipher" /> does not use a 16-byte tweak, or the file length is not a multiple of <paramref name="dataUnitSize" />.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="dataUnitSize" /> is less than 16.</exception>
	public static DataUnitRandomAccess<TCipher> Create<TCipher>(SafeFileHandle handle, TCipher cipher, int dataUnitSize, UInt128 firstDataUnitNumber = default, bool leaveOpen = false) where TCipher : class, IDataUnitCipher<TCipher>
	{
		return new DataUnitRandomAccess<TCipher>(handle, cipher, dataUnitSize, firstDataUnitNumber, leaveOpen);
	}
}
