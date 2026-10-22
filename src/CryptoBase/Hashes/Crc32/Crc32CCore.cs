namespace CryptoBase.Hashes.Crc32;

/// <summary>
/// Provides the CRC-32C (Castagnoli) checksum core.
/// </summary>
public struct Crc32CCore : IHashCore<Crc32CCore>
{
	private uint _state;

	/// <inheritdoc />
	public static int HashLength => sizeof(uint);

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static Crc32CCore IHashCore<Crc32CCore>.Create()
	{
		return new Crc32CCore { _state = Crc32Engine.InitialState };
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	void IIncrementalHashCore.Append(ReadOnlySpan<byte> source)
	{
		_state = Crc32Engine.Update<Crc32CCore>(_state, source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	readonly void IIncrementalHashCore.Finalize(Span<byte> destination)
	{
		Crc32Engine.Finalize(_state, destination);
	}
}
