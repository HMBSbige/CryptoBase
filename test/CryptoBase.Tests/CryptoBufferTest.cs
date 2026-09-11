namespace CryptoBase.Tests;

public class CryptoBufferTest
{
	[Test]
	[Arguments(0)]
	[Arguments(256)]
	[Arguments(257)]
	public async Task ByteBufferHasExactWritableLengthAcrossAllocationBoundary(int length)
	{
		byte[] snapshot;
		{
			using CryptoBuffer<byte> buffer = new(length);
			buffer.Span.Fill(0x5a);
			snapshot = [.. buffer.Span];
		}

		await Assert.That(snapshot).Count().IsEqualTo(length).And.All(static value => value is 0x5a);
	}

	[Test]
	public async Task WrappedBufferIsClearedOnDispose()
	{
		int[] values = [1, 2, 3, 4];
		{
			using CryptoBuffer<int> buffer = new(values);
			buffer.Span[2] = 42;
		}

		await Assert.That(values).All(static value => value is 0);
	}
}
