using CryptoBase.Abstractions.Macs;

namespace CryptoBase.Macs.Hmac;

/// <summary>
/// Provides one-shot and incremental keyed-hash message authentication code (HMAC) operations.
/// </summary>
/// <typeparam name="TCore">The hash core used to compute the HMAC.</typeparam>
public sealed class HmacAlgorithm<TCore> : IMacAlgorithm<HmacAlgorithm<TCore>> where TCore : unmanaged, IHmacHashCore<TCore>
{
	private HmacState<TCore> _state;
	private bool _disposed;

	private HmacAlgorithm() { }

	/// <inheritdoc />
	public static int MacLength => TCore.HashLength;

	/// <inheritdoc />
	public static HmacAlgorithm<TCore> Create(ReadOnlySpan<byte> key)
	{
		HmacAlgorithm<TCore> macAlgorithm = new();
		macAlgorithm._state.Initialize(key, true);
		return macAlgorithm;
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
		return HmacState<TCore>.Mac(key, source, destination);
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
