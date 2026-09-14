namespace CryptoBase.Hashes;

/// <summary>
/// Provides one-shot and incremental hashing.
/// </summary>
/// <typeparam name="TCore">The hash core used to compute the hash.</typeparam>
public sealed class HashAlgorithm<TCore> : IHashAlgorithm<HashAlgorithm<TCore>> where TCore : unmanaged, IHashCore<TCore>
{
	private TCore _state;
	private bool _disposed;

	private HashAlgorithm() { }

	/// <inheritdoc />
	public static int HashLength => TCore.HashLength;

	/// <inheritdoc />
	public static HashAlgorithm<TCore> Create()
	{
		return new HashAlgorithm<TCore> { _state = TCore.Create() };
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	public static int HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, TCore.HashLength, nameof(destination));

		TCore state = TCore.Create();
		Span<byte> hash = stackalloc byte[TCore.HashLength];

		state.Append(source);
		state.Finalize(hash);
		hash.CopyTo(destination);
		return TCore.HashLength;
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Append(ReadOnlySpan<byte> source)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_state.Append(source);
	}

	/// <inheritdoc />
	public void Reset()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		_state = TCore.Create();
	}

	/// <inheritdoc />
	public int GetCurrentHash(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return HashCoreUtils.FinalizeCopy(_state, destination);
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	public int GetHashAndReset(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, TCore.HashLength, nameof(destination));

		TCore currentState = _state;
		Span<byte> hash = stackalloc byte[TCore.HashLength];

		currentState.Finalize(hash);
		_state = TCore.Create();
		hash.CopyTo(destination);
		return TCore.HashLength;
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Dispose()
	{
		_disposed = true;
	}
}
