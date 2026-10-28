namespace CryptoBase.Hashes.Sha3;

/// <summary>
/// Provides cSHAKE256, the customizable variant of the SHAKE256 extendable-output function.
/// </summary>
/// <remarks>
/// <para>
/// Computes cSHAKE256 as specified in NIST SP 800-185, Sec. 3. The function name and the customization string are bit strings given as bytes, and different values give unrelated output; with both empty, cSHAKE256 is SHAKE256, per Sec. 3.3. The function name is reserved for functions that NIST defines, such as <c>"KMAC"u8</c>; applications leave it empty and choose the customization string, per Sec. 3.4. Any choice of the two leaves the security of SHAKE256, per Sec. 8.2.1: collision resistance reaches its full 256 bits from 64 bytes of output.
/// </para>
/// <para><see cref="Reset" /> and <see cref="GetHashAndReset" /> keep the function name and customization string.</para>
/// </remarks>
public sealed class CShake256Xof : IXof<CShake256Xof>
{
	private CShakeXofState<KeccakRate136> _state;
	private bool _disposed;

	private CShake256Xof() { }

	/// <summary>
	/// Creates an instance with an empty function name and customization string, which computes SHAKE256.
	/// </summary>
	/// <returns>A new initialized instance.</returns>
	public static CShake256Xof Create()
	{
		return Create(ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty);
	}

	/// <summary>
	/// Creates an instance for a function name and customization string.
	/// </summary>
	/// <param name="functionName">The function name N, reserved for functions that NIST defines; usually empty.</param>
	/// <param name="customization">The customization string S, usually UTF-8 encoded.</param>
	/// <returns>A new initialized instance.</returns>
	public static CShake256Xof Create(ReadOnlySpan<byte> functionName, ReadOnlySpan<byte> customization)
	{
		CShake256Xof xof = new();
		xof._state.Initialize(functionName, customization);
		return xof;
	}

	/// <summary>
	/// Computes the SHAKE256 output for <paramref name="source" />, which is cSHAKE256 with an empty function name and customization string.
	/// </summary>
	/// <param name="source">The data to hash.</param>
	/// <param name="destination">The buffer that receives the output; its length selects the output length.</param>
	public static void HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		CShakeXofState<KeccakRate136>.HashData(ReadOnlySpan<byte>.Empty, ReadOnlySpan<byte>.Empty, source, destination);
	}

	/// <summary>
	/// Computes the cSHAKE256 output for <paramref name="source" />.
	/// </summary>
	/// <param name="functionName">The function name N, reserved for functions that NIST defines; usually empty.</param>
	/// <param name="customization">The customization string S, usually UTF-8 encoded.</param>
	/// <param name="source">The data to hash.</param>
	/// <param name="destination">The buffer that receives the output; its length selects the output length.</param>
	public static void HashData(ReadOnlySpan<byte> functionName, ReadOnlySpan<byte> customization, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		CShakeXofState<KeccakRate136>.HashData(functionName, customization, source, destination);
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
	public CShake256Xof Clone()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		return new CShake256Xof { _state = _state };
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Dispose()
	{
		_disposed = true;
	}
}
