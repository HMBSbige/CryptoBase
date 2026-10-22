namespace CryptoBase.Hashes.Sha3;

/// <summary>
/// Provides cSHAKE128, the customizable variant of the SHAKE128 extendable-output function.
/// </summary>
/// <remarks>
/// <para>
/// Computes cSHAKE128 as specified in NIST SP 800-185, Sec. 3, over a 168-byte sponge rate. The function name and the customization string, both
/// bit strings given as bytes, are absorbed ahead of the input, so that different values give unrelated output; with both empty, cSHAKE128 is SHAKE128,
/// per Sec. 3.3. The function name is reserved for functions that NIST defines, such as <c>"KMAC"u8</c>; applications leave it empty and choose the
/// customization string, per Sec. 3.4. Any choice of the two leaves the security of SHAKE128, per Sec. 8.2.1: collision resistance reaches its full
/// 128 bits from 32 bytes of output.
/// </para>
/// <para><see cref="Reset" /> and <see cref="GetHashAndReset" /> keep the function name and customization string.</para>
/// </remarks>
public sealed class CShake128Xof : IXof<CShake128Xof>
{
	private CShakeXofState<KeccakRate168> _state;
	private bool _disposed;

	private CShake128Xof() { }

	/// <summary>
	/// Creates an instance with an empty function name and customization string, which computes SHAKE128.
	/// </summary>
	/// <returns>A new initialized instance.</returns>
	public static CShake128Xof Create()
	{
		return Create(ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);
	}

	/// <summary>
	/// Creates an instance for a function name and customization string.
	/// </summary>
	/// <param name="functionName">The function name N, reserved for functions that NIST defines; usually empty.</param>
	/// <param name="customization">The customization string S, usually UTF-8 encoded.</param>
	/// <returns>A new initialized instance.</returns>
	public static CShake128Xof Create(ReadOnlySpan<byte> functionName, ReadOnlySpan<byte> customization)
	{
		CShake128Xof xof = new();
		xof._state.Initialize(functionName, customization);
		return xof;
	}

	/// <summary>
	/// Computes the SHAKE128 output for <paramref name="source" />, which is cSHAKE128 with an empty function name and customization string.
	/// </summary>
	/// <param name="source">The data to hash.</param>
	/// <param name="destination">The buffer that receives the output; its length selects the output length.</param>
	public static void HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		CShakeXofState<KeccakRate168>.HashData(ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, source, destination);
	}

	/// <summary>
	/// Computes the cSHAKE128 output for <paramref name="source" />.
	/// </summary>
	/// <param name="functionName">The function name N, reserved for functions that NIST defines; usually empty.</param>
	/// <param name="customization">The customization string S, usually UTF-8 encoded.</param>
	/// <param name="source">The data to hash.</param>
	/// <param name="destination">The buffer that receives the output; its length selects the output length.</param>
	public static void HashData(ReadOnlySpan<byte> functionName, ReadOnlySpan<byte> customization, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		CShakeXofState<KeccakRate168>.HashData(functionName, customization, source, destination);
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Append(ReadOnlySpan<byte> source)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_state.Append(source);
	}

	/// <inheritdoc />
	public void Read(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_state.Read(destination);
	}

	/// <inheritdoc />
	public void GetCurrentHash(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_state.GetCurrentHash(destination);
	}

	/// <inheritdoc />
	public void GetHashAndReset(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_state.GetHashAndReset(destination);
	}

	/// <inheritdoc />
	public void Reset()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_state.Reset();
	}

	/// <summary>
	/// Creates an independent copy of the current state, including the position in the output stream.
	/// </summary>
	/// <returns>A new instance that continues from the current input or output position.</returns>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public CShake128Xof Clone()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		return new CShake128Xof { _state = _state };
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Dispose()
	{
		_disposed = true;
	}
}
