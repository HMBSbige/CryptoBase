namespace CryptoBase.IO;

/// <summary>
/// Provides stream extensions for MAC algorithms.
/// </summary>
public static class StreamMacExtensions
{
	/// <typeparam name="TAlgorithm">The MAC algorithm.</typeparam>
	/// <param name="mac">The MAC algorithm to append to.</param>
	extension<TAlgorithm>(TAlgorithm mac) where TAlgorithm : class, IMacAlgorithm<TAlgorithm>
	{
		/// <summary>
		/// Appends <paramref name="source" /> from its current position to the end.
		/// </summary>
		/// <param name="source">The stream to read.</param>
		/// <exception cref="ArgumentNullException"><paramref name="mac" /> or <paramref name="source" /> is <see langword="null" />.</exception>
		/// <exception cref="ArgumentException"><paramref name="source" /> does not support reading.</exception>
		/// <exception cref="ObjectDisposedException">The MAC algorithm has been disposed.</exception>
		public void Append(Stream source)
		{
			ArgumentNullException.ThrowIfNull(mac);
			ArgumentNullException.ThrowIfNull(source);
			StreamDrain.ThrowIfNotReadable(source);

			StreamDrain.ReadToEnd(source, mac, static (m, data) => m.Append(data));
		}

		/// <summary>
		/// Asynchronously appends <paramref name="source" /> from its current position to the end.
		/// </summary>
		/// <param name="source">The stream to read.</param>
		/// <param name="cancellationToken">The token used to cancel the operation.</param>
		/// <returns>A value task that completes when the stream has been consumed.</returns>
		/// <exception cref="ArgumentNullException"><paramref name="mac" /> or <paramref name="source" /> is <see langword="null" />.</exception>
		/// <exception cref="ArgumentException"><paramref name="source" /> does not support reading.</exception>
		/// <exception cref="ObjectDisposedException">The MAC algorithm has been disposed.</exception>
		public ValueTask AppendAsync(Stream source, CancellationToken cancellationToken = default)
		{
			ArgumentNullException.ThrowIfNull(mac);
			ArgumentNullException.ThrowIfNull(source);
			StreamDrain.ThrowIfNotReadable(source);

			if (cancellationToken.IsCancellationRequested)
			{
				return ValueTask.FromCanceled(cancellationToken);
			}

			return StreamDrain.ReadToEndAsync(source, mac, static (m, data) => m.Append(data), cancellationToken);
		}

		/// <summary>
		/// Computes the MAC of <paramref name="source" /> from its current position to the end.
		/// </summary>
		/// <param name="key">The key.</param>
		/// <param name="source">The stream to read.</param>
		/// <param name="destination">The buffer that receives the MAC.</param>
		/// <returns>The number of bytes written to <paramref name="destination" />.</returns>
		/// <exception cref="ArgumentNullException"><paramref name="source" /> is <see langword="null" />.</exception>
		/// <exception cref="ArgumentException"><paramref name="source" /> does not support reading, or <paramref name="key" /> is invalid.</exception>
		/// <exception cref="ArgumentOutOfRangeException"><paramref name="destination" /> is too short.</exception>
		public static int MacData(ReadOnlySpan<byte> key, Stream source, Span<byte> destination)
		{
			ArgumentNullException.ThrowIfNull(source);
			StreamDrain.ThrowIfNotReadable(source);
			ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, TAlgorithm.MacLength, nameof(destination));

			using TAlgorithm algorithm = TAlgorithm.Create(key);
			algorithm.Append(source);
			return algorithm.GetCurrentMac(destination);
		}

		/// <summary>
		/// Asynchronously computes the MAC of <paramref name="source" /> from its current position to the end.
		/// </summary>
		/// <remarks><paramref name="key" /> is consumed before this method returns, so it may be cleared before the returned task completes.</remarks>
		/// <param name="key">The key.</param>
		/// <param name="source">The stream to read.</param>
		/// <param name="destination">The buffer that receives the MAC.</param>
		/// <param name="cancellationToken">The token used to cancel the operation.</param>
		/// <returns>A value task whose result is the number of bytes written to <paramref name="destination" />.</returns>
		/// <exception cref="ArgumentNullException"><paramref name="source" /> is <see langword="null" />.</exception>
		/// <exception cref="ArgumentException"><paramref name="source" /> does not support reading, or <paramref name="key" /> is invalid.</exception>
		/// <exception cref="ArgumentOutOfRangeException"><paramref name="destination" /> is too short.</exception>
		public static ValueTask<int> MacDataAsync(ReadOnlySpan<byte> key, Stream source, Memory<byte> destination, CancellationToken cancellationToken = default)
		{
			ArgumentNullException.ThrowIfNull(source);
			StreamDrain.ThrowIfNotReadable(source);
			ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, TAlgorithm.MacLength, nameof(destination));

			if (cancellationToken.IsCancellationRequested)
			{
				return ValueTask.FromCanceled<int>(cancellationToken);
			}

			// Async methods cannot take spans, so the keyed instance is created here and the async core disposes it.
			return MacDataCoreAsync(TAlgorithm.Create(key), source, destination, cancellationToken);
		}
	}

	private static async ValueTask<int> MacDataCoreAsync<TAlgorithm>(TAlgorithm algorithm, Stream source, Memory<byte> destination, CancellationToken cancellationToken) where TAlgorithm : class, IMacAlgorithm<TAlgorithm>
	{
		using (algorithm)
		{
			await algorithm.AppendAsync(source, cancellationToken).ConfigureAwait(false);
			return algorithm.GetCurrentMac(destination.Span);
		}
	}
}
