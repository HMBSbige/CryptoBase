using CryptoBase.Hashes.Crc32;

namespace CryptoBase.Hashes.Crc32C;

/// <summary>
/// Provides the CRC-32C (Castagnoli) checksum core.
/// </summary>
public struct Crc32CHashAlgorithm : IHashCore<Crc32CHashAlgorithm>
{
	private uint _state;

	/// <inheritdoc />
	public static int HashLengthInBytes => sizeof(uint);

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	static Crc32CHashAlgorithm IHashCore<Crc32CHashAlgorithm>.Create()
	{
		return new Crc32CHashAlgorithm { _state = Crc32Engine.InitialState };
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	void IIncrementalHashCore.Append(ReadOnlySpan<byte> source)
	{
		_state = Crc32Engine.Update<Crc32CHashAlgorithm>(_state, source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	readonly void IIncrementalHashCore.Finalize(Span<byte> destination)
	{
		Crc32Engine.Finalize(_state, destination);
	}
}
