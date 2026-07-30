namespace CryptoBase.Digests.CRC32;

/// <summary>
/// Implements incremental CRC-32 using a lookup table.
/// </summary>
public class Crc32SF : IHash
{
	/// <inheritdoc />
	public virtual string Name => @"CRC-32";

	/// <inheritdoc />
	public int Length => HashConstants.Crc32Length;

	/// <inheritdoc />
	public int BlockSize => HashConstants.Crc32BlockSize;

	/// <summary>
	/// Gets the CRC lookup table.
	/// </summary>
	protected virtual Crc32Table Table => Crc32Table.Crc32;

	private uint _state;

	/// <summary>
	/// Initializes a new CRC-32 computation.
	/// </summary>
	public Crc32SF()
	{
		Reset();
	}

	/// <inheritdoc />
	public void UpdateFinal(ReadOnlySpan<byte> origin, Span<byte> destination)
	{
		Update(origin);
		GetHash(destination);
	}

	/// <inheritdoc />
	public void Update(ReadOnlySpan<byte> source)
	{
		_state = Table.Append(_state, source);
	}

	/// <inheritdoc />
	public void GetHash(Span<byte> destination)
	{
		BinaryPrimitives.WriteUInt32BigEndian(destination, _state);
		Reset();
	}

	/// <inheritdoc />
	public void Reset()
	{
		_state = uint.MinValue;
	}

	/// <inheritdoc />
	public void Dispose()
	{
		GC.SuppressFinalize(this);
	}
}
