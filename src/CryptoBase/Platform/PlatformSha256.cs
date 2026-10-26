namespace CryptoBase.Platform;

/// <summary>
/// Provides one-shot and incremental SHA-256 hashing backed by <see cref="SHA256" /> and <see cref="IncrementalHash" />.
/// </summary>
/// <remarks>
/// Platform failures throw <see cref="CryptographicException" />, leave the destination unchanged and dispose the failing instance. Disposal releases the platform state and is idempotent; subsequent instance operations other than disposal throw <see cref="ObjectDisposedException" />.
/// </remarks>
public sealed class PlatformSha256 : IHashAlgorithm<PlatformSha256>
{
	private readonly IncrementalHash _hash;
	private bool _disposed;

	private PlatformSha256(IncrementalHash hash)
	{
		_hash = hash;
	}

	/// <inheritdoc />
	public static int HashLength => SHA256.HashSizeInBytes;

	// The shortest source whose padding takes it to four blocks; below it, the fixed cost of a call to the platform outweighs the SHA extensions.
	private const int MinPreferredLength = 3 * 64 - 8;

	internal static bool HasShaExtensions { get; } = CpuIdUtils.IsSupportX86ShaEx();

	/// <summary>
	/// Returns a value that indicates whether this type is expected to be faster than the managed SHA-256 for a source of the specified length.
	/// </summary>
	/// <param name="length">The length of the source, in bytes.</param>
	/// <returns><see langword="true" /> if this type is expected to be faster; otherwise, <see langword="false" />.</returns>
	/// <remarks>
	/// It is <see langword="true" /> only on x86 and x64 processors with the SHA extensions: on Windows at any length, elsewhere from 184 bytes.
	/// </remarks>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="length" /> is negative.</exception>
	public static bool IsPreferredFor(int length)
	{
		ArgumentOutOfRangeException.ThrowIfNegative(length);

		return HasShaExtensions && (OperatingSystem.IsWindows() || length >= MinPreferredLength);
	}

	/// <inheritdoc />
	public static PlatformSha256 Create()
	{
		return new PlatformSha256(IncrementalHash.CreateHash(HashAlgorithmName.SHA256));
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	public static int HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashLength, nameof(destination));

		// The temporary buffer keeps the destination unchanged on failure and lets the source overlap it.
		using CryptoBuffer<byte> hash = new(stackalloc byte[HashLength]);
		SHA256.HashData(source, hash.Span);
		hash.Span.CopyTo(destination);
		return HashLength;
	}

	/// <inheritdoc />
	public void Append(ReadOnlySpan<byte> source)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		try
		{
			_hash.AppendData(source);
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

		// IncrementalHash has no reset of its own; finalizing into a discarded buffer resets it.
		using CryptoBuffer<byte> discarded = new(stackalloc byte[HashLength]);

		try
		{
			_hash.GetHashAndReset(discarded.Span);
		}
		catch
		{
			Dispose();
			throw;
		}
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	public int GetCurrentHash(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashLength, nameof(destination));

		using CryptoBuffer<byte> hash = new(stackalloc byte[HashLength]);

		try
		{
			_hash.GetCurrentHash(hash.Span);
		}
		catch
		{
			Dispose();
			throw;
		}

		hash.Span.CopyTo(destination);
		return HashLength;
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	public int GetHashAndReset(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashLength, nameof(destination));

		// The platform can fail after writing the hash, so it goes through a temporary buffer.
		using CryptoBuffer<byte> hash = new(stackalloc byte[HashLength]);

		try
		{
			_hash.GetHashAndReset(hash.Span);
		}
		catch
		{
			Dispose();
			throw;
		}

		hash.Span.CopyTo(destination);
		return HashLength;
	}

	/// <inheritdoc />
	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_hash.Dispose();
		_disposed = true;
	}
}
