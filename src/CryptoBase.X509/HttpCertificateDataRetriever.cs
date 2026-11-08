using System.Net.Http.Headers;

namespace CryptoBase.X509;

/// <summary>
/// Retrieves certificates, CRLs and OCSP responses with an <see cref="HttpClient" />.
/// </summary>
/// <remarks>
/// <para>
/// The client's timeout, handler, proxy and redirects apply, the timeout to the whole retrieval, the reading of the body included, and the caller owns the client; <see cref="CertificateValidationContext.Deadline" /> shortens each retrieval further.
/// A URI that is not an absolute http or https URI, a status other than a success, a connection that fails, a timeout of the client and a body longer than the limit, which is not read beyond it, all give an empty value. Only the cancellation of the token throws.
/// </para>
/// </remarks>
public sealed class HttpCertificateDataRetriever : ICertificateDataRetriever
{
	// The first buffer for a body of no declared length: most certificates and OCSP responses fit, and a long CRL declares its length.
	private const int InitialCapacity = 4096;

	private readonly HttpClient _httpClient;

	/// <summary>
	/// Initializes a retriever.
	/// </summary>
	/// <param name="httpClient">The client, which may be shared.</param>
	/// <exception cref="ArgumentNullException"><paramref name="httpClient" /> is <see langword="null" />.</exception>
	public HttpCertificateDataRetriever(HttpClient httpClient)
	{
		ArgumentNullException.ThrowIfNull(httpClient);

		_httpClient = httpClient;
	}

	/// <inheritdoc />
	/// <exception cref="ArgumentNullException"><paramref name="uri" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="maxLength" /> is not positive.</exception>
	public ValueTask<ReadOnlyMemory<byte>> GetAsync(Uri uri, int maxLength, CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(uri);
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxLength);

		return IsHttp(uri) ? ReadAsync(new HttpRequestMessage(HttpMethod.Get, uri), maxLength, cancellationToken) : default;
	}

	/// <inheritdoc />
	/// <exception cref="ArgumentNullException"><paramref name="uri" /> or <paramref name="contentType" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="maxLength" /> is not positive.</exception>
	/// <exception cref="FormatException"><paramref name="contentType" /> is not a media type.</exception>
	public ValueTask<ReadOnlyMemory<byte>> PostAsync(Uri uri, ReadOnlyMemory<byte> content, string contentType, int maxLength, CancellationToken cancellationToken)
	{
		ArgumentNullException.ThrowIfNull(uri);
		ArgumentNullException.ThrowIfNull(contentType);
		ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxLength);

		MediaTypeHeaderValue mediaType = MediaTypeHeaderValue.Parse(contentType);

		if (!IsHttp(uri))
		{
			return default;
		}

		HttpRequestMessage request = new(HttpMethod.Post, uri) { Content = new ReadOnlyMemoryContent(content) };
		request.Content.Headers.ContentType = mediaType;
		return ReadAsync(request, maxLength, cancellationToken);
	}

	private static bool IsHttp(Uri uri)
	{
		return uri is { IsAbsoluteUri: true, Scheme: "http" or "https" };
	}

	private async ValueTask<ReadOnlyMemory<byte>> ReadAsync(HttpRequestMessage request, int maxLength, CancellationToken cancellationToken)
	{
		using (request)
		{
			// HttpClient.Timeout ends at the headers of a response read as a stream, and the body could otherwise never come.
			using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

			if (_httpClient.Timeout != Timeout.InfiniteTimeSpan)
			{
				timeout.CancelAfter(_httpClient.Timeout);
			}

			try
			{
				using HttpResponseMessage response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
				long? declared = response.Content.Headers.ContentLength;

				if (!response.IsSuccessStatusCode || declared > maxLength)
				{
					return default;
				}

				Stream body = await response.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false);

				await using (body.ConfigureAwait(false))
				{
					return await ReadBodyAsync(body, declared, maxLength, timeout.Token).ConfigureAwait(false);
				}
			}
			catch (Exception e) when (e is HttpRequestException or IOException or InvalidDataException)
			{
				return default;
			}
			catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
			{
				return default;
			}
		}
	}

	// Reads at most maxLength + 1 bytes, the one beyond the limit telling that the body is too long.
	private static async ValueTask<ReadOnlyMemory<byte>> ReadBodyAsync(Stream body, long? declared, int maxLength, CancellationToken cancellationToken)
	{
		int ceiling = (int)Math.Min(maxLength + 1L, Array.MaxLength);
		byte[] buffer = GC.AllocateUninitializedArray<byte>((int)Math.Min(declared + 1 ?? InitialCapacity, ceiling));
		int filled = 0;

		while (true)
		{
			int read = await body.ReadAsync(buffer.AsMemory(filled), cancellationToken).ConfigureAwait(false);

			if (read is 0)
			{
				return buffer.AsMemory(0, filled);
			}

			filled += read;

			if (filled > maxLength)
			{
				return default;
			}

			if (filled == buffer.Length)
			{
				Array.Resize(ref buffer, (int)Math.Min(buffer.Length * 2L, ceiling));
			}
		}
	}
}
