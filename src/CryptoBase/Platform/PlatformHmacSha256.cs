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

	/// <summary>
	/// Gets a value that indicates whether this type is expected to be faster than the managed HMAC-SHA256 on the current processor.
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
