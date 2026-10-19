using CryptoBase.Abstractions.Macs;

namespace CryptoBase.Platform;

/// <summary>
/// Provides one-shot and incremental HMAC-SHA256 backed by <see cref="HMACSHA256" /> and <see cref="IncrementalHash" />.
/// </summary>
/// <remarks>
/// Failures of the platform implementation surface as <see cref="CryptographicException" />. Disposal releases the keyed platform state and is idempotent;
/// subsequent instance operations other than disposal throw <see cref="ObjectDisposedException" />.
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

	/// <summary>
	/// Gets a value that indicates whether this type is faster than the managed HMAC-SHA256 on the current processor.
	/// </summary>
	/// <remarks>
	/// It is <see langword="true" /> on x86 and x64 processors with the SHA extensions, which the managed implementation does not use.
	/// </remarks>
	public static bool IsPreferred => PlatformSha256.IsPreferred;

	/// <inheritdoc />
	public static PlatformHmacSha256 Create(ReadOnlySpan<byte> key)
	{
		return new PlatformHmacSha256(IncrementalHash.CreateHMAC(HashAlgorithmName.SHA256, key));
	}

	/// <inheritdoc />
	public static int Mac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, MacLength, nameof(destination));

		if (key.Overlaps(destination) || source.Overlaps(destination))
		{
			return MacOverlapping(key, source, destination);
		}

		return HMACSHA256.HashData(key, source, destination);
	}

	// Computing into a temporary buffer reads all of the key and source before the destination is written.
	[SkipLocalsInit]
	private static int MacOverlapping(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		using CryptoBuffer<byte> mac = new(stackalloc byte[MacLength]);
		HMACSHA256.HashData(key, source, mac.Span);
		mac.Span.CopyTo(destination);
		return MacLength;
	}

	/// <inheritdoc />
	public void Append(ReadOnlySpan<byte> source)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_hmac.AppendData(source);
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	public void Reset()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		// IncrementalHash has no reset of its own; finalizing into a discarded buffer resets it and keeps the key.
		using CryptoBuffer<byte> discarded = new(stackalloc byte[MacLength]);
		_hmac.GetHashAndReset(discarded.Span);
	}

	/// <inheritdoc />
	public int GetCurrentMac(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, MacLength, nameof(destination));

		return _hmac.GetCurrentHash(destination);
	}

	/// <inheritdoc />
	public int GetMacAndReset(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, MacLength, nameof(destination));

		return _hmac.GetHashAndReset(destination);
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
