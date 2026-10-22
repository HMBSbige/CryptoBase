namespace CryptoBase.Hashes.Crc32;

/// <summary>
/// Provides the CRC-32 (IEEE) checksum core.
/// </summary>
public struct Crc32Core : IHashCore<Crc32Core>
{
	private uint _state;

	/// <inheritdoc />
	public static int HashLength => sizeof(uint);

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static Crc32Core IHashCore<Crc32Core>.Create()
	{
		return new Crc32Core { _state = Crc32Engine.InitialState };
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	void IIncrementalHashCore.Append(ReadOnlySpan<byte> source)
	{
		_state = Crc32Engine.Update<Crc32Core>(_state, source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	readonly void IIncrementalHashCore.Finalize(Span<byte> destination)
	{
		Crc32Engine.Finalize(_state, destination);
	}
}
