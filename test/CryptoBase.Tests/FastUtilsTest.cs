using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests;

public class FastUtilsTest
{
	[Test]
	[Arguments(0)]
	[Arguments(1)]
	[Arguments(3)]
	[Arguments(4)]
	[Arguments(7)]
	[Arguments(8)]
	[Arguments(15)]
	[Arguments(16)]
	[Arguments(31)]
	[Arguments(32)]
	[Arguments(63)]
	[Arguments(64)]
	[Arguments(65)]
	[Arguments(127)]
	[Arguments(128)]
	[Arguments(129)]
	[Arguments(4095)]
	[Arguments(4096)]
	[Arguments(4097)]
	[Arguments(4096 + 127)]
	[Arguments(8192)]
	public async Task XorMatchesReferenceAtVectorAndScalarBoundaries(int length)
	{
		byte[] streamBuffer = CreateDeterministicSource(length + 1);
		byte[] sourceBuffer = CreateDeterministicSource(length + 2);
		byte[] expected = new byte[length];
		byte[] destinationBuffer = new byte[length + 2];
		destinationBuffer.AsSpan().Fill(DestinationSentinel);

		ReadOnlySpan<byte> stream = streamBuffer.AsSpan(1, length);
		ReadOnlySpan<byte> source = sourceBuffer.AsSpan(2, length);
		Span<byte> destination = destinationBuffer.AsSpan(1, length);
		ComputeXor(stream, source, expected);

		FastUtils.Xor(stream, source, destination, length);

		await Assert.That(destinationBuffer.AsMemory(1, length)).IsEquivalentTo(expected, CollectionOrdering.Matching);
		await Assert.That(destinationBuffer[0]).IsEqualTo(DestinationSentinel);
		await Assert.That(destinationBuffer[^1]).IsEqualTo(DestinationSentinel);
	}

	[Test]
	[Arguments(0)]
	[Arguments(1)]
	[Arguments(3)]
	[Arguments(4)]
	[Arguments(7)]
	[Arguments(8)]
	[Arguments(11)]
	[Arguments(12)]
	[Arguments(15)]
	public async Task XorLess16MatchesReferenceForEveryScalarTail(int length)
	{
		byte[] stream = CreateDeterministicSource(length);
		byte[] sourceBuffer = CreateDeterministicSource(length + 1);
		byte[] expected = new byte[length];
		byte[] actual = new byte[length + 1];
		actual.AsSpan().Fill(DestinationSentinel);
		ReadOnlySpan<byte> source = sourceBuffer.AsSpan(1, length);
		ComputeXor(stream, source, expected);

		FastUtils.XorLess16(stream, source, actual, length);

		await AssertOutput(actual, expected, length);
	}

	[Test]
	[Arguments(129)]
	[Arguments(8193)]
	public async Task XorSupportsStreamAsExactInPlaceDestination(int length)
	{
		byte[] stream = CreateDeterministicSource(length);
		byte[] sourceBuffer = CreateDeterministicSource(length + 1);
		byte[] expected = new byte[length];
		ReadOnlySpan<byte> source = sourceBuffer.AsSpan(1, length);
		ComputeXor(stream, source, expected);

		FastUtils.Xor(stream, source, stream, length);

		await Assert.That(stream).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(129)]
	[Arguments(8193)]
	public async Task XorSupportsSourceAsExactInPlaceDestination(int length)
	{
		byte[] stream = CreateDeterministicSource(length);
		byte[] sourceBuffer = CreateDeterministicSource(length + 1);
		byte[] expected = new byte[length];
		Span<byte> source = sourceBuffer.AsSpan(1, length);
		ComputeXor(stream, source, expected);

		FastUtils.Xor(stream, source, source, length);

		await Assert.That(sourceBuffer.AsMemory(1, length)).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	private static void ComputeXor(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right, Span<byte> destination)
	{
		for (int i = 0; i < destination.Length; ++i)
		{
			destination[i] = (byte)(left[i] ^ right[i]);
		}
	}
}
