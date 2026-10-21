namespace CryptoBase.IO;

/// <summary>
/// Provides stream extensions for hash algorithms.
/// </summary>
public static class StreamHashExtensions
{
	/// <typeparam name="TAlgorithm">The hash algorithm.</typeparam>
	/// <param name="hasher">The hasher to append to.</param>
	extension<TAlgorithm>(TAlgorithm hasher) where TAlgorithm : class, IHashAlgorithm<TAlgorithm>
	{
		/// <summary>
		/// Appends <paramref name="source" /> from its current position to the end.
		/// </summary>
		/// <param name="source">The stream to read.</param>
		/// <exception cref="ArgumentNullException"><paramref name="hasher" /> or <paramref name="source" /> is <see langword="null" />.</exception>
		/// <exception cref="ArgumentException"><paramref name="source" /> does not support reading.</exception>
		/// <exception cref="ObjectDisposedException">The hasher has been disposed.</exception>
		public void Append(Stream source)
		{
			StreamDrain.Append(hasher, source);
		}

		/// <summary>
		/// Asynchronously appends <paramref name="source" /> from its current position to the end.
		/// </summary>
		/// <param name="source">The stream to read.</param>
		/// <param name="cancellationToken">The token used to cancel the operation.</param>
		/// <returns>A value task that completes when the stream has been consumed.</returns>
		/// <exception cref="ArgumentNullException"><paramref name="hasher" /> or <paramref name="source" /> is <see langword="null" />.</exception>
		/// <exception cref="ArgumentException"><paramref name="source" /> does not support reading.</exception>
		/// <exception cref="ObjectDisposedException">The hasher has been disposed.</exception>
		public ValueTask AppendAsync(Stream source, CancellationToken cancellationToken = default)
		{
			return StreamDrain.AppendAsync(hasher, source, cancellationToken);
		}

		/// <summary>
		/// Computes the hash of <paramref name="source" /> from its current position to the end.
		/// </summary>
		/// <param name="source">The stream to read.</param>
		/// <param name="destination">The buffer that receives the hash.</param>
		/// <returns>The number of bytes written to <paramref name="destination" />.</returns>
		/// <exception cref="ArgumentNullException"><paramref name="source" /> is <see langword="null" />.</exception>
		/// <exception cref="ArgumentException"><paramref name="source" /> does not support reading.</exception>
		/// <exception cref="ArgumentOutOfRangeException"><paramref name="destination" /> is too short.</exception>
		public static int HashData(Stream source, Span<byte> destination)
		{
			ArgumentNullException.ThrowIfNull(source);
			StreamDrain.ThrowIfNotReadable(source);
			ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, TAlgorithm.HashLength, nameof(destination));

			using TAlgorithm algorithm = TAlgorithm.Create();
			algorithm.Append(source);
			return algorithm.GetCurrentHash(destination);
		}

		/// <summary>
		/// Asynchronously computes the hash of <paramref name="source" /> from its current position to the end.
		/// </summary>
		/// <param name="source">The stream to read.</param>
		/// <param name="destination">The buffer that receives the hash.</param>
		/// <param name="cancellationToken">The token used to cancel the operation.</param>
		/// <returns>A value task whose result is the number of bytes written to <paramref name="destination" />.</returns>
		/// <exception cref="ArgumentNullException"><paramref name="source" /> is <see langword="null" />.</exception>
		/// <exception cref="ArgumentException"><paramref name="source" /> does not support reading.</exception>
		/// <exception cref="ArgumentOutOfRangeException"><paramref name="destination" /> is too short.</exception>
		public static ValueTask<int> HashDataAsync(Stream source, Memory<byte> destination, CancellationToken cancellationToken = default)
		{
			ArgumentNullException.ThrowIfNull(source);
			StreamDrain.ThrowIfNotReadable(source);
			ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, TAlgorithm.HashLength, nameof(destination));

			if (cancellationToken.IsCancellationRequested)
			{
				return ValueTask.FromCanceled<int>(cancellationToken);
			}

			return HashDataCoreAsync<TAlgorithm>(source, destination, cancellationToken);
		}
	}

	private static async ValueTask<int> HashDataCoreAsync<TAlgorithm>(Stream source, Memory<byte> destination, CancellationToken cancellationToken) where TAlgorithm : class, IHashAlgorithm<TAlgorithm>
	{
		using TAlgorithm algorithm = TAlgorithm.Create();
		await algorithm.AppendAsync(source, cancellationToken).ConfigureAwait(false);
		return algorithm.GetCurrentHash(destination.Span);
	}
}
