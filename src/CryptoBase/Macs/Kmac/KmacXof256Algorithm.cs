using CryptoBase.Abstractions;
using CryptoBase.Hashes.Sha3;

namespace CryptoBase.Macs.Kmac;

/// <summary>
/// Provides KMACXOF256, the extendable-output variant of KMAC256.
/// </summary>
/// <remarks>
/// <para>
/// Computes KMACXOF256 as specified in NIST SP 800-185, Sec. 4.3.1, over a 136-byte sponge rate: KMAC256 with the output length encoded as 0, so that the output is a stream, of which a destination of any length receives the start, and a shorter output is a prefix of every longer one. Unlike with <see cref="Kmac256Algorithm" />, the output does not depend on the length requested, so an application that needs tags of more than one length should prefer KMAC256. The key and the customization string may have any length, empty included.
/// </para>
/// <para>
/// The first nonempty <see cref="Read" /> ends the input, and each read continues where the previous one stopped; until <see cref="Reset" />, <see cref="Append" />, <see cref="GetCurrentHash" /> and <see cref="GetHashAndReset" /> then throw <see cref="InvalidOperationException" />.
/// A reset keeps the key and customization string, which the instance holds until disposal. Disposal erases the state, key included, and is idempotent; subsequent operations other than disposal throw <see cref="ObjectDisposedException" />.
/// </para>
/// </remarks>
public sealed class KmacXof256Algorithm : IIncrementalAlgorithm, IDisposable
{
	private KmacXofState<KeccakRate136> _state;
	private bool _disposed;

	private KmacXof256Algorithm() { }

	/// <summary>
	/// Creates an instance for a key and customization string.
	/// </summary>
	/// <param name="key">The key K, of any length.</param>
	/// <param name="customization">The customization string S, usually UTF-8 encoded; empty by default.</param>
	/// <returns>A new initialized instance.</returns>
	public static KmacXof256Algorithm Create(ReadOnlySpan<byte> key, ReadOnlySpan<byte> customization = default)
	{
		// Allocating first leaves no copy of the key behind should allocation fail.
		KmacXof256Algorithm xof = new();
		xof._state.Initialize(key, customization);
		return xof;
	}

	/// <summary>
	/// Computes the start of the KMACXOF256 output stream for <paramref name="source" />.
	/// </summary>
	/// <param name="key">The key K, of any length.</param>
	/// <param name="source">The data to authenticate.</param>
	/// <param name="destination">The buffer that receives the output; its length selects the output length.</param>
	/// <param name="customization">The customization string S, usually UTF-8 encoded; empty by default.</param>
	public static void HashData(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination, ReadOnlySpan<byte> customization = default)
	{
		KmacXofState<KeccakRate136>.HashData(key, source, destination, customization);
	}

	/// <summary>
	/// Appends <paramref name="source" /> to the current input.
	/// </summary>
	/// <param name="source">The data to append.</param>
	/// <exception cref="InvalidOperationException">The instance is reading; call <see cref="Reset" /> first.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Append(ReadOnlySpan<byte> source)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_state.Append(source);
	}

	/// <summary>
	/// Writes the next bytes of the output stream; the first nonempty read ends the input.
	/// </summary>
	/// <remarks>An empty <paramref name="destination" /> leaves the state unchanged.</remarks>
	/// <param name="destination">The buffer that receives the output.</param>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public void Read(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_state.Read(destination);
	}

	/// <summary>
	/// Writes the start of the output stream for the input so far without changing the state.
	/// </summary>
	/// <param name="destination">The buffer that receives the output; its length selects the output length.</param>
	/// <exception cref="InvalidOperationException">The instance is reading; call <see cref="Reset" /> first.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public void GetCurrentHash(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_state.GetCurrentHash(destination);
	}

	/// <summary>
	/// Writes the start of the output stream for the input so far, then resets the state, keeping the key and customization string.
	/// </summary>
	/// <param name="destination">The buffer that receives the output; its length selects the output length.</param>
	/// <exception cref="InvalidOperationException">The instance is reading; call <see cref="Reset" /> first.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public void GetHashAndReset(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_state.GetHashAndReset(destination);
	}

	/// <summary>
	/// Resets the state, discarding the current input and leaving the reading state while keeping the key and customization string.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public void Reset()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_state.Reset();
	}

	/// <summary>
	/// Creates an independent copy of the current state, key included, and of the position in the output stream.
	/// </summary>
	/// <returns>A new instance that continues from the current input or output position; disposing it erases its copy of the key.</returns>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public KmacXof256Algorithm Clone()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		return new KmacXof256Algorithm { _state = _state };
	}

	/// <inheritdoc />
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
