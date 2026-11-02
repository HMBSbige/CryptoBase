using CryptoBase.Ciphers;

namespace CryptoBase.Platform;

/// <summary>
/// Provides AES-GCM authenticated encryption backed by <see cref="AesGcm" />.
/// </summary>
/// <remarks>
/// Authentication failures return <see langword="false" /> and clear the output. Other platform failures throw, clear the output and dispose the failing instance. Disposal releases the keyed platform state and is idempotent; subsequent instance operations other than disposal throw <see cref="ObjectDisposedException" />.
/// </remarks>
public sealed class PlatformAesGcm : IAeadCipher<PlatformAesGcm>
{
	private readonly AesGcm _aesGcm;
	private bool _disposed;

	private PlatformAesGcm(AesGcm aesGcm)
	{
		_aesGcm = aesGcm;
	}

	/// <inheritdoc />
	public static int NonceSize => 12;

	/// <inheritdoc />
	public static int TagSize => 16;

	// Below it, the fixed cost of a call to the platform outweighs its VAES kernels; with 128-bit keys the two break even about here.
	private const int MinPreferredLength = 8 * 1024;

	/// <summary>
	/// Returns a value that indicates whether this type is expected to be faster than the managed AES-GCM for a message of the specified length.
	/// </summary>
	/// <param name="length">The length of the message, in bytes.</param>
	/// <returns><see langword="true" /> if this type is expected to be faster; otherwise, <see langword="false" />.</returns>
	/// <remarks>
	/// It is <see langword="true" /> only on x86 and x64 processors with VAES and AVX-512, from 8 KiB.
	/// </remarks>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="length" /> is negative.</exception>
	public static bool IsPreferredFor(int length)
	{
		ArgumentOutOfRangeException.ThrowIfNegative(length);

		// The runtime reports Pclmulqdq.V512 only with VAES and AVX-512, which the platform library uses for its 512-bit kernels.
		return length >= MinPreferredLength && Pclmulqdq.V512.IsSupported && AesGcm.IsSupported;
	}

	/// <inheritdoc />
	public static PlatformAesGcm Create(scoped ReadOnlySpan<byte> key)
	{
		if (key.Length is not (16 or 24 or 32))
		{
			ThrowHelper.ThrowArgumentOutOfRangeException<int>(nameof(key), "Key length must be 16/24/32 bytes");
		}

		return new PlatformAesGcm(new AesGcm(key, TagSize));
	}

	/// <inheritdoc />
	public void Encrypt(scoped ReadOnlySpan<byte> nonce, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination, scoped Span<byte> tag, scoped ReadOnlySpan<byte> associatedData = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		AeadBufferGuard.ValidateInput(nonce, source, destination, tag, NonceSize, TagSize);
		destination = destination.Slice(0, source.Length);

		using CryptoBuffer<byte> nonceCopy = CopyIfOverlapping(nonce, destination);
		using CryptoBuffer<byte> associatedDataCopy = CopyIfOverlapping(associatedData, destination);

		try
		{
			_aesGcm.Encrypt(nonceCopy.Span.IsEmpty ? nonce : nonceCopy.Span, source, destination, tag, associatedDataCopy.Span.IsEmpty ? associatedData : associatedDataCopy.Span);
		}
		catch
		{
			destination.ZeroMemory();
			tag.ZeroMemory();
			Dispose();
			throw;
		}
	}

	/// <inheritdoc />
	public bool TryDecrypt(scoped ReadOnlySpan<byte> nonce, scoped ReadOnlySpan<byte> source, scoped ReadOnlySpan<byte> tag, scoped Span<byte> destination, scoped ReadOnlySpan<byte> associatedData = default)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		AeadBufferGuard.ValidateInput(nonce, source, destination, tag, NonceSize, TagSize);
		destination = destination.Slice(0, source.Length);

		using CryptoBuffer<byte> nonceCopy = CopyIfOverlapping(nonce, destination);
		using CryptoBuffer<byte> associatedDataCopy = CopyIfOverlapping(associatedData, destination);

		try
		{
			_aesGcm.Decrypt(nonceCopy.Span.IsEmpty ? nonce : nonceCopy.Span, source, tag, destination, associatedDataCopy.Span.IsEmpty ? associatedData : associatedDataCopy.Span);
			return true;
		}
		catch (AuthenticationTagMismatchException)
		{
			destination.ZeroMemory();
			return false;
		}
		catch
		{
			destination.ZeroMemory();
			Dispose();
			throw;
		}
	}

	// The platform does not promise to read its inputs before writing the output, so an input that overlaps the output is copied first.
	private static CryptoBuffer<byte> CopyIfOverlapping(ReadOnlySpan<byte> input, ReadOnlySpan<byte> output)
	{
		if (!ByteSpans.Overlaps(input, output))
		{
			return default;
		}

		CryptoBuffer<byte> copy = new(input.Length);
		input.CopyTo(copy.Span);
		return copy;
	}

	/// <inheritdoc />
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_aesGcm.Dispose();
		_disposed = true;
	}
}
