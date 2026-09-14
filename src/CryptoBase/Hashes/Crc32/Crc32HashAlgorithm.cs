namespace CryptoBase.Hashes.Crc32;

/// <summary>
/// Provides the CRC-32 (IEEE) checksum core.
/// </summary>
public struct Crc32HashAlgorithm : IHashCore<Crc32HashAlgorithm>
{
	private uint _state;

	/// <inheritdoc />
	public static int HashLength => sizeof(uint);

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static Crc32HashAlgorithm IHashCore<Crc32HashAlgorithm>.Create()
	{
		return new Crc32HashAlgorithm { _state = Crc32Engine.InitialState };
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	void IIncrementalHashCore.Append(ReadOnlySpan<byte> source)
	{
		_state = Crc32Engine.Update<Crc32HashAlgorithm>(_state, source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	readonly void IIncrementalHashCore.Finalize(Span<byte> destination)
	{
		Crc32Engine.Finalize(_state, destination);
	}
}
