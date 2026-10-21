using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.IO;

/// <summary>A memory stream that reports that it cannot be read.</summary>
internal sealed class WriteOnlyMemoryStream : MemoryStream
{
	public override bool CanRead => false;
}

/// <summary>A memory stream whose reads return at most <c>maxReadSize</c> bytes and no data at or past <c>end</c>, while <see cref="Stream.Length" /> still reports all of it.</summary>
internal class LimitedReadMemoryStream : MemoryStream
{
	private readonly int _maxReadSize;
	private readonly long _end;

	public LimitedReadMemoryStream(int maxReadSize = int.MaxValue, long end = long.MaxValue)
	{
		_maxReadSize = maxReadSize;
		_end = end;
	}

	public LimitedReadMemoryStream(byte[] buffer, int maxReadSize) : base(buffer, false)
	{
		_maxReadSize = maxReadSize;
		_end = long.MaxValue;
	}

	// MemoryStream.ReadAsync forwards to these overloads, so asynchronous reads are limited too.
	public override int Read(byte[] buffer, int offset, int count)
	{
		return base.Read(buffer, offset, Limit(count));
	}

	public override int Read(Span<byte> buffer)
	{
		return base.Read(buffer.Slice(0, Limit(buffer.Length)));
	}

	private int Limit(int count)
	{
		return (int)Math.Clamp(Math.Min(_end - Position, _maxReadSize), 0, count);
	}
}

/// <summary>A <see cref="LimitedReadMemoryStream" /> whose asynchronous reads and writes complete asynchronously.</summary>
internal sealed class YieldingMemoryStream : LimitedReadMemoryStream
{
	public YieldingMemoryStream()
	{
	}

	public YieldingMemoryStream(byte[] buffer, int maxReadSize) : base(buffer, maxReadSize)
	{
	}

	public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
	{
		await Task.Yield();
		return Read(buffer.Span);
	}

	public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
	{
		await Task.Yield();
		Write(buffer.Span);
	}
}

/// <summary>A memory stream whose reads throw <see cref="IOException" />.</summary>
internal sealed class FailingReadMemoryStream : MemoryStream
{
	public override int Read(byte[] buffer, int offset, int count)
	{
		throw new IOException("Read failed.");
	}

	public override int Read(Span<byte> buffer)
	{
		throw new IOException("Read failed.");
	}
}

/// <summary>A memory stream whose reads past the end fill the buffer, as a failing decoder may, and then throw <see cref="IOException" />.</summary>
internal sealed class FailingAtEndMemoryStream : MemoryStream
{
	public const byte Garbage = 0x5A;

	public FailingAtEndMemoryStream(byte[] buffer) : base(buffer, false)
	{
	}

	public override int Read(Span<byte> buffer)
	{
		if (Position < Length)
		{
			return base.Read(buffer);
		}

		buffer.Fill(Garbage);
		throw new IOException("Read failed.");
	}

	public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
	{
		await Task.Yield();
		return Read(buffer.Span);
	}
}

/// <summary>The streams that a disposed algorithm must reject, of which all but the last give the algorithm no data.</summary>
public enum AppendSourceKind
{
	NullStream,
	EmptyStream,
	StreamAtEnd,
	NonEmptyStream
}

internal static class AppendSources
{
	public static Stream Create(AppendSourceKind kind)
	{
		return kind switch
		{
			AppendSourceKind.NullStream => Stream.Null,
			AppendSourceKind.EmptyStream => new MemoryStream(),
			AppendSourceKind.StreamAtEnd => new MemoryStream(CreateDeterministicSource(257), false) { Position = 257 },
			AppendSourceKind.NonEmptyStream => new MemoryStream(CreateDeterministicSource(257), false) { Position = 11 },
			_ => throw new ArgumentOutOfRangeException(nameof(kind))
		};
	}
}

/// <summary>Calls the synchronous overload of a stream operation, or the asynchronous one when <c>useAsync</c> is set.</summary>
internal static class StreamTestUtils
{
	private static readonly int[] ChunkSizes = [1, 7, 13, 509, 4099];

	public static async Task WriteAsync(Stream stream, ReadOnlyMemory<byte> buffer, bool useAsync)
	{
		if (useAsync)
		{
			await stream.WriteAsync(buffer);
		}
		else
		{
			stream.Write(buffer.Span);
		}
	}

	public static async Task WriteAsync(Stream stream, byte[] buffer, int offset, int count, bool useAsync)
	{
		if (useAsync)
		{
			await stream.WriteAsync(buffer, offset, count);
		}
		else
		{
			stream.Write(buffer, offset, count);
		}
	}

	public static async Task FlushAsync(Stream stream, bool useAsync)
	{
		if (useAsync)
		{
			await stream.FlushAsync();
		}
		else
		{
			stream.Flush();
		}
	}

	public static async Task CopyToAsync(Stream source, Stream destination, bool useAsync)
	{
		if (useAsync)
		{
			await source.CopyToAsync(destination);
		}
		else
		{
			source.CopyTo(destination);
		}
	}

	public static async Task DisposeAsync(Stream stream, bool useAsync)
	{
		if (useAsync)
		{
			await stream.DisposeAsync();
		}
		else
		{
			stream.Dispose();
		}
	}

	/// <summary>Reads <paramref name="stream" /> to its end in calls of varying sizes and returns the bytes read.</summary>
	public static async Task<byte[]> ReadInChunksAsync(Stream stream, bool useAsync)
	{
		using MemoryStream output = new();
		byte[] buffer = new byte[ChunkSizes[^1]];

		for (int i = 0; ; ++i)
		{
			Memory<byte> chunk = buffer.AsMemory(0, ChunkSizes[i % ChunkSizes.Length]);
			int read = useAsync ? await stream.ReadAsync(chunk) : stream.Read(chunk.Span);

			if (read is 0)
			{
				return output.ToArray();
			}

			output.Write(buffer, 0, read);
		}
	}

	/// <summary>Writes <paramref name="source" /> to <paramref name="stream" /> in calls of varying sizes.</summary>
	public static async Task WriteInChunksAsync(Stream stream, byte[] source, bool useAsync)
	{
		for (int offset = 0, i = 0; offset < source.Length; ++i)
		{
			int size = Math.Min(ChunkSizes[i % ChunkSizes.Length], source.Length - offset);
			await WriteAsync(stream, source.AsMemory(offset, size), useAsync);
			offset += size;
		}
	}
}
