using CryptoBase.Abstractions.Macs;

namespace CryptoBase.Macs.Hmac;

/// <summary>
/// Provides one-shot and incremental keyed-hash message authentication code (HMAC) operations.
/// </summary>
/// <typeparam name="THash">The hash core used to compute the HMAC.</typeparam>
public sealed class HmacAlgorithm<THash> : IMacAlgorithm<HmacAlgorithm<THash>> where THash : unmanaged, IHmacHashCore<THash>
{
	private HmacState<THash> _state;
	private bool _disposed;

	private HmacAlgorithm() { }

	/// <inheritdoc />
	public static int MacLength => THash.HashLength;

	/// <inheritdoc />
	public static HmacAlgorithm<THash> Create(ReadOnlySpan<byte> key)
	{
		HmacAlgorithm<THash> macAlgorithm = new();

		try
		{
			macAlgorithm._state.Initialize(key);
			return macAlgorithm;
		}
		catch
		{
			macAlgorithm.Dispose();
			throw;
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
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Reset()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_state.Reset();
	}

	/// <inheritdoc />
	public int GetCurrentMac(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _state.GetCurrentMac(destination);
	}

	/// <inheritdoc />
	public int GetMacAndReset(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		return _state.GetMacAndReset(destination);
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int Mac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		return HmacState<THash>.Mac(key, source, destination);
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
