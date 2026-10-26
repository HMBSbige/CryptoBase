using CryptoBase.Abstractions.Macs;

namespace CryptoBase.Platform;

/// <summary>
/// Provides one-shot and incremental HMAC-SHA256 backed by <see cref="HMACSHA256" /> and <see cref="IncrementalHash" />.
/// </summary>
/// <remarks>
/// Platform failures throw <see cref="CryptographicException" />, leave the destination unchanged and dispose the failing instance. Disposal releases the keyed platform state and is idempotent; subsequent instance operations other than disposal throw <see cref="ObjectDisposedException" />.
/// </remarks>
public sealed class PlatformHmacSha256 : IMacAlgorithm<PlatformHmacSha256>
{
	private readonly IncrementalHash _hmac;
	private bool _disposed;

	private PlatformHmacSha256(IncrementalHash hmac)
	{
		_hmac = hmac;
	}

	/// <inheritdoc />
	public static int MacLength => HMACSHA256.HashSizeInBytes;

	// Below it, the fixed cost of a call to the platform outweighs the SHA extensions.
	private const int MinPreferredLength = 256;

	/// <summary>
	/// Returns a value that indicates whether this type is expected to be faster than the managed HMAC-SHA256 for a message of the specified length and a key of at most 64 bytes.
	/// </summary>
	/// <param name="length">The length of the message, in bytes.</param>
	/// <returns><see langword="true" /> if this type is expected to be faster; otherwise, <see langword="false" />.</returns>
	/// <remarks>
	/// It is <see langword="true" /> only on x86 and x64 processors with the SHA extensions: on Windows at any length, elsewhere from 256 bytes.
	/// </remarks>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="length" /> is negative.</exception>
	public static bool IsPreferredFor(int length)
	{
		ArgumentOutOfRangeException.ThrowIfNegative(length);

		return PlatformSha256.HasShaExtensions && (OperatingSystem.IsWindows() || length >= MinPreferredLength);
	}

	/// <inheritdoc />
	public static PlatformHmacSha256 Create(ReadOnlySpan<byte> key)
	{
		return new PlatformHmacSha256(IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key));
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	public static int Mac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, MacLength, nameof(destination));

		// The temporary buffer keeps the destination unchanged on failure and lets the key and source overlap it.
		using CryptoBuffer<byte> mac = new(stackalloc byte[MacLength]);
		HMACSHA256.HashData(key, source, mac.Span);
		mac.Span.CopyTo(destination);
		return MacLength;
	}

	/// <inheritdoc />
	public void Append(ReadOnlySpan<byte> source)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		try
		{
			_hmac.AppendData(source);
		}
		catch
		{
			Dispose();
			throw;
		}
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	public void Reset()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		// IncrementalHash has no reset of its own; finalizing into a discarded buffer resets it and keeps the key.
		using CryptoBuffer<byte> discarded = new(stackalloc byte[MacLength]);

		try
		{
			_hmac.GetHashAndReset(discarded.Span);
		}
		catch
		{
			Dispose();
			throw;
		}
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	public int GetCurrentMac(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, MacLength, nameof(destination));

		using CryptoBuffer<byte> mac = new(stackalloc byte[MacLength]);

		try
		{
			_hmac.GetCurrentHash(mac.Span);
		}
		catch
		{
			Dispose();
			throw;
		}

		mac.Span.CopyTo(destination);
		return MacLength;
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	public int GetMacAndReset(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, MacLength, nameof(destination));

		// The platform can fail after writing the MAC, so it goes through a temporary buffer.
		using CryptoBuffer<byte> mac = new(stackalloc byte[MacLength]);

		try
		{
			_hmac.GetHashAndReset(mac.Span);
		}
		catch
		{
			Dispose();
			throw;
		}

		mac.Span.CopyTo(destination);
		return MacLength;
	}

	/// <inheritdoc />
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_hmac.Dispose();
		_disposed = true;
	}
}
