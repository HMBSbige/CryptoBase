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

		try
		{
			ReadToEnd(source, buffer, sink, append);
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(buffer);
		}
	}

	public static async ValueTask ReadToEndAsync<TSink>(Stream source, TSink sink, Action<TSink, ReadOnlySpan<byte>> append, CancellationToken cancellationToken)
	{
		byte[] buffer = ArrayPool<byte>.Shared.Rent(BufferSize);

		try
		{
			await ReadToEndAsync(source, buffer, sink, append, cancellationToken).ConfigureAwait(false);
		}
		finally
		{
			ArrayPool<byte>.Shared.Return(buffer);
		}
	}

	// Takes the buffer, which it erases before returning, so that tests can inspect what is left in it.
	internal static void ReadToEnd<TSink>(Stream source, byte[] buffer, TSink sink, Action<TSink, ReadOnlySpan<byte>> append)
	{
		int used = 0;
		bool completed = false;

		try
		{
			int length;

			while ((length = source.Read(buffer)) > 0)
			{
				used = Math.Max(used, length);
				append(sink, buffer.AsSpan(0, length));
			}

			completed = true;
		}
		finally
		{
			Erase(buffer, used, completed);
		}
	}

	internal static async ValueTask ReadToEndAsync<TSink>(Stream source, byte[] buffer, TSink sink, Action<TSink, ReadOnlySpan<byte>> append, CancellationToken cancellationToken)
	{
		int used = 0;
		bool completed = false;

		try
		{
			int length;

			while ((length = await source.ReadAsync(buffer, cancellationToken).ConfigureAwait(false)) > 0)
			{
				used = Math.Max(used, length);
				append(sink, buffer.AsSpan(0, length));
			}

			completed = true;
		}
		finally
		{
			Erase(buffer, used, completed);
		}
	}

	// Completed reads fill at most the first used bytes, so erasing only those keeps short streams from paying for the whole buffer. A read that throws may
	// have written anywhere in the buffer first, as a decoder may before it finds corrupt data, so a failure erases all of it.
	private static void Erase(byte[] buffer, int used, bool completed)
	{
		CryptographicOperations.ZeroMemory(completed ? buffer.AsSpan(0, used) : buffer);
	}
}
