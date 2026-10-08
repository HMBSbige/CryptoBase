namespace CryptoBase.Hashes.Blake2b;

/// <summary>
/// Provides the BLAKE2b-256 hash core.
/// </summary>
/// <remarks>Computes unkeyed BLAKE2b with a 32-byte digest, as specified in RFC 7693.</remarks>
public struct Blake2b256HashAlgorithm : IHmacHashCore<Blake2b256HashAlgorithm>
{
	private const int HashSizeInBytes = 32;

	private Blake2bCore _state;

	/// <inheritdoc />
	public static int HashLength => HashSizeInBytes;

	/// <inheritdoc />
	public static int HmacBlockSize => Blake2bCore.BlockSizeInBytes;

	[SkipLocalsInit]
	static Blake2b256HashAlgorithm IHashCore<Blake2b256HashAlgorithm>.Create()
	{
		Unsafe.SkipInit(out Blake2b256HashAlgorithm hashAlgorithm);
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
