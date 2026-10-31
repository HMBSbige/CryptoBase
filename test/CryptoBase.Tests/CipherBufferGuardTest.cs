using CryptoBase.Internal;

namespace CryptoBase.Tests;

public class CipherBufferGuardTest
{
	[Test]
	public async Task SourceDestinationOverlapRejectsOverlapsExceptAtTheSameStart()
	{
		byte[] first = new byte[ByteSpansTest.BufferLength];
		byte[] second = new byte[ByteSpansTest.BufferLength];
		(byte[] Buffer, int Start, int Length)[] spans = [.. ByteSpansTest.Spans(first, second)];
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
					failures.Add($"{ByteSpansTest.Describe(a, first)} and {ByteSpansTest.Describe(b, first)}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}
}
