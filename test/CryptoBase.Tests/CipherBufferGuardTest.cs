using CryptoBase.Internal;

namespace CryptoBase.Tests;

public class CipherBufferGuardTest
{
	private const int BufferLength = 9;

	private static IEnumerable<(byte[] Buffer, int Start, int Length)> Spans(byte[] first, byte[] second)
	{
		for (int start = 0; start <= BufferLength; ++start)
		{
			for (int length = 0; start + length <= BufferLength; ++length)
			{
				yield return (first, start, length);
			}
		}

		yield return (second, 0, 0);
		yield return (second, 0, 1);
		yield return (second, 1, BufferLength - 1);
	}

	[Test]
	public async Task OverlapsMatchesMemoryExtensions()
	{
		byte[] first = new byte[BufferLength];
		byte[] second = new byte[BufferLength];
		(byte[] Buffer, int Start, int Length)[] spans = [.. Spans(first, second)];
		List<string> failures = [];

		foreach ((byte[] Buffer, int Start, int Length) a in spans)
		{
			foreach ((byte[] Buffer, int Start, int Length) b in spans)
			{
				ReadOnlySpan<byte> span = a.Buffer.AsSpan(a.Start, a.Length);
				ReadOnlySpan<byte> other = b.Buffer.AsSpan(b.Start, b.Length);

				if (CipherBufferGuard.Overlaps(span, other) != span.Overlaps(other))
				{
					failures.Add($"{Describe(a, first)} and {Describe(b, first)}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task SourceDestinationOverlapRejectsOverlapsExceptAtTheSameStart()
	{
		byte[] first = new byte[BufferLength];
		byte[] second = new byte[BufferLength];
		(byte[] Buffer, int Start, int Length)[] spans = [.. Spans(first, second)];
		List<string> failures = [];

		foreach ((byte[] Buffer, int Start, int Length) a in spans)
		{
			foreach ((byte[] Buffer, int Start, int Length) b in spans)
			{
				ReadOnlySpan<byte> source = a.Buffer.AsSpan(a.Start, a.Length);
				ReadOnlySpan<byte> destination = b.Buffer.AsSpan(b.Start, b.Length);
				bool expected = source.Overlaps(destination, out int offset) && offset is not 0;
				bool rejected = false;

				try
				{
					CipherBufferGuard.SourceDestinationOverlap(source, destination);
				}
				catch (ArgumentException exception) when (exception.ParamName is "destination")
				{
					rejected = true;
				}

				if (rejected != expected)
				{
					failures.Add($"{Describe(a, first)} and {Describe(b, first)}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	private static string Describe((byte[] Buffer, int Start, int Length) span, byte[] first)
	{
		return $"{(span.Buffer == first ? "first" : "second")}[{span.Start}..+{span.Length}]";
	}
}
