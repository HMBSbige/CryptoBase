using CryptoBase.Internal;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests;

public class FastUtilsTest
{
	[Test]
	[MatrixDataSource]
	public async Task XorMatchesReferenceAtVectorAndScalarBoundaries([Matrix(0, 1, 2, 3, 4, 5, 6, 7, 8, 15, 16, 31, 32, 63, 64, 65, 127, 128, 129, 4095, 4096, 4097, 4096 + 127, 8192)] int length)
	{
		byte[] streamBuffer = CreateDeterministicSource(length + 1);
		byte[] sourceBuffer = CreateDeterministicSource(length + 2);
		byte[] expected = new byte[length];
		byte[] destinationBuffer = new byte[length + 2];
		PrepareDestination(destinationBuffer);

		ReadOnlySpan<byte> stream = streamBuffer.AsSpan(1, length);
		ReadOnlySpan<byte> source = sourceBuffer.AsSpan(2, length);
		Span<byte> destination = destinationBuffer.AsSpan(1, length);
		ComputeXor(stream, source, expected);

		FastUtils.Xor(stream, source, destination, length);

		await AssertOutput(destinationBuffer, 1, expected);
	}

	[Test]
	[MatrixDataSource]
	public async Task XorLess16MatchesReferenceForEveryScalarTail([MatrixRange<int>(0, 15)] int length)
	{
		byte[] stream = CreateDeterministicSource(length);
		byte[] sourceBuffer = CreateDeterministicSource(length + 1);
		byte[] expected = new byte[length];
		byte[] actual = new byte[length + 1];
		PrepareDestination(actual);
		ReadOnlySpan<byte> source = sourceBuffer.AsSpan(1, length);
		ComputeXor(stream, source, expected);

		FastUtils.XorLess16(stream, source, actual, length);

		await AssertOutput(actual, expected, length);
	}

	[Test]
	[MatrixDataSource]
	public async Task XorSupportsStreamAsExactInPlaceDestination([Matrix(2, 3, 7, 13, 15, 45, 129, 8193)] int length)
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
	[MatrixDataSource]
	public async Task XorSupportsSourceAsExactInPlaceDestination([Matrix(2, 3, 7, 13, 15, 45, 129, 8193)] int length)
	{
		byte[] stream = CreateDeterministicSource(length);
		byte[] sourceBuffer = CreateDeterministicSource(length + 1);
		byte[] expected = new byte[length];
		Span<byte> source = sourceBuffer.AsSpan(1, length);
		ComputeXor(stream, source, expected);

		FastUtils.Xor(stream, source, source, length);

		await Assert.That(sourceBuffer.AsMemory(1, length)).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[MatrixDataSource]
	public async Task XorLess16SupportsSourceAsExactInPlaceDestination([MatrixRange<int>(0, 15)] int length)
	{
		byte[] stream = CreateDeterministicSource(length);
		byte[] sourceBuffer = CreateDeterministicSource(length + 1);
		byte[] expected = new byte[length];
		Span<byte> source = sourceBuffer.AsSpan(1, length);
		ComputeXor(stream, source, expected);

		FastUtils.XorLess16(stream, source, source, length);

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
