namespace CryptoBase.Hashes;

/// <summary>
/// Provides one-shot and incremental use of an extendable-output function.
/// </summary>
/// <typeparam name="TCore">The XOF core used to compute the output.</typeparam>
public sealed class Xof<TCore> : IXof<Xof<TCore>> where TCore : unmanaged, IXofCore<TCore>
{
	private TCore _state;
	private bool _reading;
	private bool _disposed;

	private Xof() { }

	/// <inheritdoc />
	public static Xof<TCore> Create()
	{
		return new Xof<TCore> { _state = TCore.Create() };
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	public static void HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		TCore state = TCore.Create();
		state.Append(source);
		state.Read(destination);
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Append(ReadOnlySpan<byte> source)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ThrowHelper.ThrowIfXofReading(_reading);
		_state.Append(source);
	}

	/// <inheritdoc />
	public void Read(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		if (destination.IsEmpty)
		{
			return;
		}

		_reading = true;
		_state.Read(destination);
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	public void GetCurrentHash(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ThrowHelper.ThrowIfXofReading(_reading);

		TCore state = _state;
		state.Read(destination);
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	public void GetHashAndReset(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ThrowHelper.ThrowIfXofReading(_reading);

		_state.Read(destination);
		_state = TCore.Create();
	}

	/// <inheritdoc />
	public void Reset()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		_state = TCore.Create();
		_reading = false;
	}

	/// <summary>
	/// Creates an independent copy of the current state, including the position in the output stream.
	/// </summary>
	/// <returns>A new instance that continues from the current input or output position.</returns>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public Xof<TCore> Clone()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		return new Xof<TCore> { _state = _state, _reading = _reading };
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Dispose()
	{
		_disposed = true;
	}
}
