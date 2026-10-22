using CryptoBase.Hashes.Blake2b;

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
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static int HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, TCore.HashLength, nameof(destination));

		if (UseBlake2bHashData())
		{
			Blake2bState.HashData(source, destination, TCore.HashLength);
			return TCore.HashLength;
		}

		TCore state = TCore.Create();
		state.Append(source);
		state.Finalize(destination);
		return TCore.HashLength;
	}

	// Keep the type checks out of HashData's IL budget so other hash cores retain their inlined finalization.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool UseBlake2bHashData()
	{
		return typeof(TCore) == typeof(Blake2b256HashAlgorithm) || typeof(TCore) == typeof(Blake2b512HashAlgorithm);
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
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	public int GetCurrentHash(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, TCore.HashLength, nameof(destination));

		TCore state = _state;
		state.Finalize(destination);
		return TCore.HashLength;
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	public int GetHashAndReset(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, TCore.HashLength, nameof(destination));

		_state.Finalize(destination);
		_state = TCore.Create();
		return TCore.HashLength;
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Dispose()
	{
		_disposed = true;
	}
}
