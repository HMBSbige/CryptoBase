using CryptoBase.IO;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.IO;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class StreamDrainTest
{
	[Test]
	[MatrixDataSource]
	public async Task FailedReadErasesTheWholeBuffer([Matrix(0, 100)] int sourceLength, [Matrix] bool useAsync)
	{
		byte[] source = CreateDeterministicSource(sourceLength);
		byte[] buffer = new byte[StreamDrain.BufferSize];
		PrepareDestination(buffer);
		using FailingAtEndMemoryStream stream = new(source);
		using MemoryStream sink = new();

		if (useAsync)
		{
			await Assert.That(() => StreamDrain.ReadToEndAsync(stream, buffer, sink, static (s, data) => s.Write(data), CancellationToken.None).AsTask()).ThrowsExactly<IOException>();
		}
		else
		{
			await Assert.That(() => StreamDrain.ReadToEnd(stream, buffer, sink, static (s, data) => s.Write(data))).ThrowsExactly<IOException>();
		}

		using (Assert.Multiple())
		{
			await Assert.That(sink.ToArray()).IsEquivalentTo(source, CollectionOrdering.Matching);
			await Assert.That(buffer).All(static value => value is 0);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task CompletedReadErasesOnlyTheBytesItUsed([Matrix] bool useAsync)
	{
		const int maxReadSize = 1000;
		byte[] source = CreateDeterministicSource(4099);
		byte[] buffer = new byte[StreamDrain.BufferSize];
		PrepareDestination(buffer);
		using YieldingMemoryStream stream = new(source, maxReadSize);
		using MemoryStream sink = new();

		if (useAsync)
		{
			await StreamDrain.ReadToEndAsync(stream, buffer, sink, static (s, data) => s.Write(data), CancellationToken.None);
		}
		else
		{
			StreamDrain.ReadToEnd(stream, buffer, sink, static (s, data) => s.Write(data));
		}

		using (Assert.Multiple())
		{
			await Assert.That(sink.ToArray()).IsEquivalentTo(source, CollectionOrdering.Matching);
			await Assert.That(buffer.AsMemory(0, maxReadSize)).All(static value => value is 0);
			await Assert.That(buffer.AsMemory(maxReadSize)).All(static value => value is DestinationSentinel);
		}
	}
}
