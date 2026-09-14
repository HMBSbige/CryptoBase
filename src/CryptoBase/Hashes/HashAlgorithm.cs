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

		Unsafe.SkipInit(out TCore state);
		Span<byte> hash = stackalloc byte[TCore.HashLength];

		try
		{
			state = TCore.Create();
			state.Append(source);
			state.Finalize(hash);
			hash.CopyTo(destination);
			return TCore.HashLength;
		}
		finally
		{
			hash.ZeroMemory();
			state.ZeroMemory();
		}
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Append(ReadOnlySpan<byte> source)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_state.Append(source);
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	public void Reset()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		Unsafe.SkipInit(out TCore state);

		try
		{
			state = TCore.Create();
			_state.ZeroMemory();
			_state = state;
		}
		finally
		{
			state.ZeroMemory();
		}
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
		Unsafe.SkipInit(out TCore resetState);
		Span<byte> hash = stackalloc byte[TCore.HashLength];

		try
		{
			currentState.Finalize(hash);
			resetState = TCore.Create();
			_state.ZeroMemory();
			_state = resetState;
			hash.CopyTo(destination);
			return TCore.HashLength;
		}
		finally
		{
			hash.ZeroMemory();
			currentState.ZeroMemory();
			resetState.ZeroMemory();
		}
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_state.ZeroMemory();
		_disposed = true;
	}
}
