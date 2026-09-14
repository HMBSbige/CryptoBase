using System.Buffers;

namespace CryptoBase.Hashes;

/// <summary>
/// Provides stream extensions for computing hash values.
/// </summary>
public static class HashUtils
{
	private const int BufferSize = 4096;

	/// <summary>
	/// Provides methods for hashing the remaining stream data.
	/// </summary>
	/// <param name="inputStream">The stream to read from its current position.</param>
	extension(Stream inputStream)
	{
		/// <summary>
		/// Computes the hash of the remaining stream data into a caller-provided buffer.
		/// </summary>
		/// <typeparam name="TAlgorithm">The hash algorithm.</typeparam>
		/// <param name="destination">The buffer that receives the hash.</param>
		/// <returns>The number of bytes written to <paramref name="destination" />.</returns>
		/// <exception cref="ArgumentNullException"><paramref name="inputStream" /> is <see langword="null" />.</exception>
		/// <exception cref="ArgumentOutOfRangeException"><paramref name="destination" /> is too short.</exception>
		/// <exception cref="ArgumentException"><paramref name="inputStream" /> does not support reading.</exception>
		public int ComputeHash<TAlgorithm>(Span<byte> destination) where TAlgorithm : class, IHashAlgorithm<TAlgorithm>
		{
			ArgumentNullException.ThrowIfNull(inputStream);
			ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, TAlgorithm.HashLength, nameof(destination));

			ThrowIfNotReadable(inputStream);

			return ProcessStream<TAlgorithm>(inputStream, destination);
		}

		/// <summary>
		/// Asynchronously computes the hash of the remaining stream data into a caller-provided buffer.
		/// </summary>
		/// <typeparam name="TAlgorithm">The hash algorithm.</typeparam>
		/// <param name="destination">The buffer that receives the hash.</param>
		/// <param name="cancellationToken">The token used to cancel the operation.</param>
		/// <returns>A value task whose result is the number of bytes written to <paramref name="destination" />.</returns>
		/// <exception cref="ArgumentNullException"><paramref name="inputStream" /> is <see langword="null" />.</exception>
		/// <exception cref="ArgumentOutOfRangeException"><paramref name="destination" /> is too short.</exception>
		/// <exception cref="ArgumentException"><paramref name="inputStream" /> does not support reading.</exception>
		public ValueTask<int> ComputeHashAsync<TAlgorithm>(Memory<byte> destination, CancellationToken cancellationToken = default) where TAlgorithm : class, IHashAlgorithm<TAlgorithm>
		{
			ArgumentNullException.ThrowIfNull(inputStream);
			ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, TAlgorithm.HashLength, nameof(destination));

			ThrowIfNotReadable(inputStream);

			if (cancellationToken.IsCancellationRequested)
			{
				return ValueTask.FromCanceled<int>(cancellationToken);
			}

			return ProcessStreamAsync<TAlgorithm>(inputStream, destination, cancellationToken);
		}
	}

	private static void ThrowIfNotReadable(Stream inputStream)
	{
		if (!inputStream.CanRead)
		{
			throw new ArgumentException("Stream does not support reading.", nameof(inputStream));
		}
	}

	private static int ProcessStream<TAlgorithm>(Stream inputStream, Span<byte> destination) where TAlgorithm : class, IHashAlgorithm<TAlgorithm>
	{
		using TAlgorithm hashAlgorithm = TAlgorithm.Create();
		byte[] buffer = ArrayPool<byte>.Shared.Rent(BufferSize);

		try
		{
			int length;

			while ((length = inputStream.Read(buffer)) > 0)
			{
				hashAlgorithm.Append(buffer.AsSpan(0, length));
			}

			return hashAlgorithm.GetCurrentHash(destination);
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(buffer, true);
		}
	}

	private static async ValueTask<int> ProcessStreamAsync<TAlgorithm>(Stream inputStream, Memory<byte> destination, CancellationToken cancellationToken) where TAlgorithm : class, IHashAlgorithm<TAlgorithm>
	{
		using TAlgorithm hashAlgorithm = TAlgorithm.Create();
		byte[] buffer = ArrayPool<byte>.Shared.Rent(BufferSize);

		try
		{
			int length;

			while ((length = await inputStream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
			{
				hashAlgorithm.Append(buffer.AsSpan(0, length));
			}

			return hashAlgorithm.GetCurrentHash(destination.Span);
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(buffer, true);
		}
	}
}
