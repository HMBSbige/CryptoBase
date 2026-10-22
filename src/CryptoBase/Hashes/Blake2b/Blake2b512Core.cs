namespace CryptoBase.Hashes.Blake2b;

/// <summary>
/// Provides the BLAKE2b-512 hash core.
/// </summary>
/// <remarks>Computes unkeyed BLAKE2b with a 64-byte digest, as specified in RFC 7693.</remarks>
public struct Blake2b512Core : IHmacHashCore<Blake2b512Core>
{
	private const int HashSizeInBytes = 64;

	private Blake2bState _state;

	/// <inheritdoc />
	public static int HashLength => HashSizeInBytes;

	/// <inheritdoc />
	public static int HmacBlockSize => Blake2bState.BlockSizeInBytes;

	[SkipLocalsInit]
	static Blake2b512Core IHashCore<Blake2b512Core>.Create()
	{
		Unsafe.SkipInit(out Blake2b512Core hashAlgorithm);
		hashAlgorithm._state.Initialize(HashSizeInBytes);
		return hashAlgorithm;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	void IIncrementalHashCore.Append(ReadOnlySpan<byte> source)
	{
		_state.Append(source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal void PrecompressBuffer()
	{
		_state.PrecompressBuffer();
	}

	void IIncrementalHashCore.Finalize(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashLength, nameof(destination));
		_state.Finalize(destination, HashSizeInBytes);
	}
}
