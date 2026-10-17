namespace CryptoBase.IO;

/// <summary>
/// Reads a stream to its end and passes each chunk to a sink.
/// </summary>
internal static class StreamDrain
{
	// BLAKE3 hashes appends of a whole group (16 KiB) or more in place instead of copying them, and fewer reads mean fewer calls into the stream. A power of
	// two keeps aligned reads on BLAKE3 subtree boundaries, and 64 KiB stays below the large object heap threshold.
	public const int BufferSize = 64 * 1024;

	public static void ThrowIfNotReadable(Stream source)
	{
		if (!source.CanRead)
		{
			throw new ArgumentException("Stream does not support reading.", nameof(source));
		}
	}

	public static void ReadToEnd<TSink>(Stream source, TSink sink, Action<TSink, ReadOnlySpan<byte>> append)
	{
		byte[] buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
		int used = 0;

		try
		{
			int length;

			while ((length = source.Read(buffer)) > 0)
			{
				used = Math.Max(used, length);
				append(sink, buffer.AsSpan(0, length));
			}
		}
		finally
		{
			Return(buffer, used);
		}
	}

	public static async ValueTask ReadToEndAsync<TSink>(Stream source, TSink sink, Action<TSink, ReadOnlySpan<byte>> append, CancellationToken cancellationToken)
	{
		byte[] buffer = ArrayPool<byte>.Shared.Rent(BufferSize);
		int used = 0;

		try
		{
			int length;

			while ((length = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
			{
				used = Math.Max(used, length);
				append(sink, buffer.AsSpan(0, length));
			}
		}
		finally
		{
			Return(buffer, used);
		}
	}

	// Reads fill at most the first used bytes, so erasing only those keeps short streams from paying for the whole buffer.
	private static void Return(byte[] buffer, int used)
	{
		CryptographicOperations.ZeroMemory(buffer.AsSpan(0, used));
		ArrayPool<byte>.Shared.Return(buffer);
	}
}
