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
