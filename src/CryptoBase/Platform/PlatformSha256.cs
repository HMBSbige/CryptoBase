namespace CryptoBase.Platform;

/// <summary>
/// Provides one-shot and incremental SHA-256 hashing backed by <see cref="SHA256" /> and <see cref="IncrementalHash" />.
/// </summary>
/// <remarks>
/// Failures of the platform implementation surface as <see cref="CryptographicException" />. Disposal releases the platform state and is idempotent;
/// subsequent instance operations other than disposal throw <see cref="ObjectDisposedException" />.
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

	/// <summary>
	/// Gets a value that indicates whether this type is faster than the managed SHA-256 on the current processor.
	/// </summary>
	/// <remarks>
	/// It is <see langword="true" /> on x86 and x64 processors with the SHA extensions, which the managed implementation does not use.
	/// </remarks>
	public static bool IsPreferred { get; } = CpuIdUtils.IsSupportX86ShaEx();

	/// <inheritdoc />
	public static PlatformSha256 Create()
	{
		return new PlatformSha256(IncrementalHash.CreateHash(HashAlgorithmName.SHA256));
	}

	/// <inheritdoc />
	public static int HashData(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashLength, nameof(destination));

		if (source.Overlaps(destination))
		{
			return HashOverlapping(source, destination);
		}

		return SHA256.HashData(source, destination);
	}

	// Hashing into a temporary buffer reads all of the source before the destination is written.
	[SkipLocalsInit]
	private static int HashOverlapping(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		using CryptoBuffer<byte> hash = new(stackalloc byte[HashLength]);
		SHA256.HashData(source, hash.Span);
		hash.Span.CopyTo(destination);
		return HashLength;
	}

	/// <inheritdoc />
	public void Append(ReadOnlySpan<byte> source)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		_hash.AppendData(source);
	}

	/// <inheritdoc />
	[SkipLocalsInit]
	public void Reset()
	{
		ObjectDisposedException.ThrowIf(_disposed, this);

		// IncrementalHash has no reset of its own; finalizing into a discarded buffer resets it.
		using CryptoBuffer<byte> discarded = new(stackalloc byte[HashLength]);
		_hash.GetHashAndReset(discarded.Span);
	}

	/// <inheritdoc />
	public int GetCurrentHash(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashLength, nameof(destination));

		return _hash.GetCurrentHash(destination);
	}

	/// <inheritdoc />
	public int GetHashAndReset(Span<byte> destination)
	{
		ObjectDisposedException.ThrowIf(_disposed, this);
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, HashLength, nameof(destination));

		return _hash.GetHashAndReset(destination);
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
