namespace CryptoBase.Hashes.Blake2;

/// <summary>
/// Provides the BLAKE2b-256 hash core.
/// </summary>
/// <remarks>Computes unkeyed BLAKE2b with a 32-byte digest, as specified in RFC 7693.</remarks>
public struct Blake2b256Core : IHmacHashCore<Blake2b256Core>
{
	private const int HashSizeInBytes = 32;

	private Blake2bState _state;

	/// <inheritdoc />
	public static int HashLength => HashSizeInBytes;

	/// <inheritdoc />
	public static int HmacBlockSize => Blake2bState.BlockSizeInBytes;

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void Initialize(out Blake2b256Core core)
	{
		Unsafe.SkipInit(out core);
		core._state.Initialize(HashSizeInBytes);
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Append(ReadOnlySpan<byte> source)
	{
		_state.Append(source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal void PrecompressBuffer()
	{
		_state.PrecompressBuffer();
	}

	/// <inheritdoc />
	public void Finalize(Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashLength, nameof(destination));
		_state.Finalize(destination, HashSizeInBytes);
	}
}
