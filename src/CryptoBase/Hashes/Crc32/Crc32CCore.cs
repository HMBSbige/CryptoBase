namespace CryptoBase.Hashes.Crc32;

/// <summary>
/// Provides the CRC-32C (Castagnoli) checksum core.
/// </summary>
public struct Crc32CCore : IHashCore<Crc32CCore>
{
	private uint _state;

	/// <inheritdoc />
	public static int HashLength => sizeof(uint);

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static void Initialize(out Crc32CCore core)
	{
		core._state = Crc32Engine.InitialState;
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Append(ReadOnlySpan<byte> source)
	{
		_state = Crc32Engine.Update<Crc32CCore>(_state, source);
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly void Finalize(Span<byte> destination)
	{
		Crc32Engine.Finalize(_state, destination);
	}
}
