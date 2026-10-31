namespace CryptoBase.IO.Storage;

internal static class PositionalStorageExtensions
{
	/// <summary>
	/// Fills <paramref name="buffer" /> with the bytes starting at <paramref name="offset" />, or fails when the backend ends first.
	/// </summary>
	/// <returns><see langword="false" /> if the backend ends before <paramref name="buffer" /> is full; its content is then unspecified.</returns>
	public static bool TryReadExactly(this IPositionalStorage storage, Span<byte> buffer, long offset)
	{
		while (!buffer.IsEmpty)
		{
			int read = storage.Read(buffer, offset);

			if (read is 0)
			{
				return false;
			}

			buffer = buffer.Slice(read);
			offset += read;
		}

		return true;
	}

	/// <inheritdoc cref="TryReadExactly" />
	public static async ValueTask<bool> TryReadExactlyAsync(this IPositionalStorage storage, Memory<byte> buffer, long offset, CancellationToken cancellationToken)
	{
		while (!buffer.IsEmpty)
		{
			int read = await storage.ReadAsync(buffer, offset, cancellationToken).ConfigureAwait(false);

			if (read is 0)
			{
				return false;
			}

			buffer = buffer.Slice(read);
			offset += read;
		}

		return true;
	}
}
