using CryptoBase.Abstractions;
using CryptoBase.Hashes.Sha3;

namespace CryptoBase.Macs.Kmac;

/// <summary>
/// Provides KMAC256, the message authentication code built on cSHAKE256.
/// </summary>
/// <remarks>
/// <para>
/// Computes KMAC256 as specified in NIST SP 800-185, Sec. 4, over a 136-byte sponge rate: cSHAKE256 with the function name <c>"KMAC"</c> and the
/// customization string absorbs the key, padded to a whole block, then the message, then the output length L in bits. The key and the customization
/// string may have any length, empty included; different customization strings give unrelated tags for the same key and message. The key length in
/// bits bounds the security strength, which reaches its full 256 bits from a 32-byte key, per Sec. 8.4.1; Sec. 8.4.2 asks for tags of at least
/// 32 bits, 4 bytes, and a risk assessment below 64 bits.
/// </para>
/// <para>
/// The destination length selects L: a destination of n bytes receives the tag for L = 8n bits. Since L is part of the input, tags of different
/// lengths are unrelated, so truncating a longer tag does not give a shorter one. An empty destination throws, since an empty tag would verify
/// every message. <see cref="KmacXof256Algorithm" /> computes KMACXOF256, whose output is a stream.
/// </para>
/// <para>
/// A reset keeps the key and customization string, which the instance holds until disposal. Disposal erases the state, key included, and is idempotent;
/// subsequent operations other than disposal throw <see cref="ObjectDisposedException" />.
/// </para>
/// </remarks>
public sealed class Kmac256Algorithm : IIncrementalAlgorithm, IDisposable
{
	private KmacState<KeccakRate136> _state;
	private bool _disposed;

	private Kmac256Algorithm() { }

	/// <summary>
	/// Creates an instance for a key and customization string.
	/// </summary>
	/// <param name="key">The key K, of any length.</param>
	/// <param name="customization">The customization string S, usually UTF-8 encoded; empty by default.</param>
	/// <returns>A new initialized instance.</returns>
	public static Kmac256Algorithm Create(ReadOnlySpan<byte> key, ReadOnlySpan<byte> customization = default)
	{
		// Allocating first leaves no copy of the key behind should allocation fail.
		Kmac256Algorithm kmac = new();
		kmac._state.Initialize(key, customization);
		return kmac;
	}

	/// <summary>
	/// Computes the KMAC256 tag of <paramref name="source" />.
	/// </summary>
	/// <param name="key">The key K, of any length.</param>
	/// <param name="source">The data to authenticate.</param>
	/// <param name="destination">The buffer that receives the tag; its length selects the output length L.</param>
	/// <param name="customization">The customization string S, usually UTF-8 encoded; empty by default.</param>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="destination" /> is empty.</exception>
	public static void Mac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination, ReadOnlySpan<byte> customization = default)
	{
		KmacState<KeccakRate136>.Mac(key, source, destination, customization);
	}

	/// <inheritdoc />
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Append(ReadOnlySpan<byte> source)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_state.Append(source);
	}

	/// <summary>
	/// Writes the tag of the input so far without changing the state.
	/// </summary>
	/// <param name="destination">The buffer that receives the tag; its length selects the output length L.</param>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="destination" /> is empty.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public void GetCurrentMac(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_state.GetCurrentMac(destination);
	}

	/// <summary>
	/// Writes the tag of the input so far, then resets the state, keeping the key and customization string.
	/// </summary>
	/// <param name="destination">The buffer that receives the tag; its length selects the output length L.</param>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="destination" /> is empty.</exception>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public void GetMacAndReset(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_state.GetMacAndReset(destination);
	}

	/// <summary>
	/// Resets the state, discarding the current input while keeping the key and customization string.
	/// </summary>
	/// <exception cref="ObjectDisposedException">The instance has been disposed.</exception>
	public void Reset()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_state.Reset();
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
