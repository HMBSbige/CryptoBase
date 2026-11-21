using CryptoBase.Ciphers;

namespace CryptoBase.Platform;

/// <summary>
/// Provides AES-GCM authenticated encryption backed by <see cref="AesGcm" />.
/// </summary>
/// <remarks>
/// Authentication failures return <see langword="false" /> and clear the output.
/// Other platform failures throw, clear the output and dispose the failing instance.
/// Disposal releases the keyed platform state and is idempotent; subsequent instance operations other than disposal throw <see cref="ObjectDisposedException" />.
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

	// Below it, the fixed cost of a call to the platform outweighs its VAES kernels.
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

		// A callee cannot return stack memory, so the copies are made here.
		using CryptoBuffer<byte> nonceCopy = !ByteSpans.Overlaps(nonce, destination) ? default : CryptoBuffer<byte>.ShouldUsePool(nonce.Length) ? new CryptoBuffer<byte>(nonce.Length) : new CryptoBuffer<byte>(stackalloc byte[nonce.Length]);
		using CryptoBuffer<byte> associatedDataCopy = !ByteSpans.Overlaps(associatedData, destination) ? default : CryptoBuffer<byte>.ShouldUsePool(associatedData.Length) ? new CryptoBuffer<byte>(associatedData.Length) : new CryptoBuffer<byte>(stackalloc byte[associatedData.Length]);
		nonce = CopyInto(nonce, nonceCopy.Span);
		associatedData = CopyInto(associatedData, associatedDataCopy.Span);

		try
		{
			_aesGcm.Encrypt(nonce, source, destination, tag, associatedData);
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

		// A callee cannot return stack memory, so the copies are made here.
		using CryptoBuffer<byte> nonceCopy = !ByteSpans.Overlaps(nonce, destination) ? default : CryptoBuffer<byte>.ShouldUsePool(nonce.Length) ? new CryptoBuffer<byte>(nonce.Length) : new CryptoBuffer<byte>(stackalloc byte[nonce.Length]);
		using CryptoBuffer<byte> associatedDataCopy = !ByteSpans.Overlaps(associatedData, destination) ? default : CryptoBuffer<byte>.ShouldUsePool(associatedData.Length) ? new CryptoBuffer<byte>(associatedData.Length) : new CryptoBuffer<byte>(stackalloc byte[associatedData.Length]);
		nonce = CopyInto(nonce, nonceCopy.Span);
		associatedData = CopyInto(associatedData, associatedDataCopy.Span);

		try
		{
			_aesGcm.Decrypt(nonce, source, tag, destination, associatedData);
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
	private static ReadOnlySpan<byte> CopyInto(ReadOnlySpan<byte> input, Span<byte> copy)
	{
		if (copy.IsEmpty)
		{
			return input;
		}

		input.CopyTo(copy);
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
