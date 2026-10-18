using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes;
using CryptoBase.Hashes.Blake3;
using CryptoBase.Hashes.Sha256;
using CryptoBase.IO;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.IO;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class StreamHashExtensionsTest
{
	[Test]
	[MatrixDataSource]
	public async Task HashDataStartsAtCurrentPosition([Matrix] bool useAsync)
	{
		const int startOffset = 137;
		byte[] source = CreateDeterministicSource(StreamDrain.BufferSize * 2 + 257);
		byte[] expected = SHA256.HashData(source.AsSpan(startOffset));
		byte[] destination = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength + 1];
		PrepareDestination(destination);
		using MemoryStream stream = new(source, false);
		stream.Position = startOffset;

		int written = useAsync
			? await HashAlgorithm<Sha256HashAlgorithm>.HashDataAsync(stream, destination)
			: HashAlgorithm<Sha256HashAlgorithm>.HashData(stream, destination);

		await AssertOutput(destination, expected, written);
		await Assert.That(stream.Position).IsEqualTo(stream.Length);
	}

	[Test]
	[MatrixDataSource]
	public async Task HashDataRejectsShortDestinationBeforeReading([Matrix] bool useAsync)
	{
		byte[] source = CreateDeterministicSource(257);
		byte[] destination = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength - 1];
		PrepareDestination(destination);
		using MemoryStream stream = new(source, false);
		stream.Position = 11;

		using (Assert.Multiple())
		{
			if (useAsync)
			{
				await Assert.That(() => HashAlgorithm<Sha256HashAlgorithm>.HashDataAsync(stream, destination).AsTask()).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
			}
			else
			{
				await Assert.That(() => HashAlgorithm<Sha256HashAlgorithm>.HashData(stream, destination)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
			}
			await Assert.That(stream.Position).IsEqualTo(11);
			await Assert.That(destination).All(static value => value is DestinationSentinel);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task HashDataContinuesAfterShortReads([Matrix(0, 257)] int sourceLength, [Matrix] bool useAsync)
	{
		byte[] source = CreateDeterministicSource(sourceLength);
		byte[] expected = SHA256.HashData(source);
		byte[] destination = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength];
		using MemoryStream stream = new LimitedReadMemoryStream(source, 7);

		int written = useAsync
			? await HashAlgorithm<Sha256HashAlgorithm>.HashDataAsync(stream, destination)
			: HashAlgorithm<Sha256HashAlgorithm>.HashData(stream, destination);

		await AssertOutput(destination, expected, written);
		await Assert.That(stream.Position).IsEqualTo(stream.Length);
	}

	[Test]
	public async Task HashDataRejectsNullAndUnreadableStreamsBeforeWriting()
	{
		byte[] destination = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength];
		PrepareDestination(destination);

		using (Assert.Multiple())
		{
			await Assert.That(() => HashAlgorithm<Sha256HashAlgorithm>.HashData((Stream)null!, destination)).ThrowsExactly<ArgumentNullException>().WithParameterName("source");
			await Assert.That(() => HashAlgorithm<Sha256HashAlgorithm>.HashData(new WriteOnlyMemoryStream(), destination)).ThrowsExactly<ArgumentException>().WithParameterName("source");
			await Assert.That(() => HashAlgorithm<Sha256HashAlgorithm>.HashDataAsync(null!, destination).AsTask()).ThrowsExactly<ArgumentNullException>().WithParameterName("source");
			await Assert.That(() => HashAlgorithm<Sha256HashAlgorithm>.HashDataAsync(new WriteOnlyMemoryStream(), destination).AsTask()).ThrowsExactly<ArgumentException>().WithParameterName("source");
			await Assert.That(destination).All(static value => value is DestinationSentinel);
		}
	}

	[Test]
	public async Task AppendRejectsNullArgumentsAndUnreadableStreams()
	{
		using HashAlgorithm<Sha256HashAlgorithm> hasher = HashAlgorithm<Sha256HashAlgorithm>.Create();
		HashAlgorithm<Sha256HashAlgorithm>? nullHasher = null;
		using MemoryStream stream = new(CreateDeterministicSource(257), false);
		stream.Position = 11;

		using (Assert.Multiple())
		{
			await Assert.That(() => nullHasher!.Append(stream)).ThrowsExactly<ArgumentNullException>().WithParameterName("hasher");
			await Assert.That(() => nullHasher!.AppendAsync(stream).AsTask()).ThrowsExactly<ArgumentNullException>().WithParameterName("hasher");
			await Assert.That(() => hasher.Append((Stream)null!)).ThrowsExactly<ArgumentNullException>().WithParameterName("source");
			await Assert.That(() => hasher.AppendAsync(null!).AsTask()).ThrowsExactly<ArgumentNullException>().WithParameterName("source");
			await Assert.That(() => hasher.Append(new WriteOnlyMemoryStream())).ThrowsExactly<ArgumentException>().WithParameterName("source");
			await Assert.That(() => hasher.AppendAsync(new WriteOnlyMemoryStream()).AsTask()).ThrowsExactly<ArgumentException>().WithParameterName("source");
			await Assert.That(stream.Position).IsEqualTo(11);
			await AssertCurrentHash(hasher, SHA256.HashData(ReadOnlySpan<byte>.Empty));
		}
	}

	[Test]
	public async Task HashDataAsyncHonorsPreCanceledTokenBeforeReading()
	{
		byte[] source = CreateDeterministicSource(257);
		byte[] destination = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength];
		PrepareDestination(destination);
		using MemoryStream stream = new(source, false);
		using CancellationTokenSource cancellation = new();
		cancellation.Cancel();

		OperationCanceledException exception = (await Assert.That(() => HashAlgorithm<Sha256HashAlgorithm>.HashDataAsync(stream, destination, cancellation.Token).AsTask()).Throws<OperationCanceledException>())!;

		using (Assert.Multiple())
		{
			await Assert.That(exception.CancellationToken).IsEqualTo(cancellation.Token);
			await Assert.That(stream.Position).IsZero();
			await Assert.That(destination).All(static value => value is DestinationSentinel);
		}
	}

	[Test]
	public async Task AppendAsyncHonorsPreCanceledTokenBeforeReading()
	{
		using HashAlgorithm<Sha256HashAlgorithm> hasher = HashAlgorithm<Sha256HashAlgorithm>.Create();
		using MemoryStream stream = new(CreateDeterministicSource(257), false);
		using CancellationTokenSource cancellation = new();
		cancellation.Cancel();

		OperationCanceledException exception = (await Assert.That(() => hasher.AppendAsync(stream, cancellation.Token).AsTask()).Throws<OperationCanceledException>())!;

		using (Assert.Multiple())
		{
			await Assert.That(exception.CancellationToken).IsEqualTo(cancellation.Token);
			await Assert.That(stream.Position).IsZero();
			await AssertCurrentHash(hasher, SHA256.HashData(ReadOnlySpan<byte>.Empty));
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task AppendMixesWithSpanAppend([Matrix] bool useAsync)
	{
		const int startOffset = 5;
		byte[] header = CreateDeterministicSource(19);
		byte[] body = CreateDeterministicSource(4096 * 2 + 33);
		byte[] trailer = CreateDeterministicSource(7);
		byte[] expected = SHA256.HashData(Concat(Concat(header, body.AsSpan(startOffset)), trailer));
		using HashAlgorithm<Sha256HashAlgorithm> hasher = HashAlgorithm<Sha256HashAlgorithm>.Create();
		using MemoryStream stream = new LimitedReadMemoryStream(body, 1000);
		stream.Position = startOffset;

		hasher.Append(header);

		if (useAsync)
		{
			await hasher.AppendAsync(stream);
		}
		else
		{
			hasher.Append(stream);
		}

		hasher.Append(trailer);

		await AssertCurrentHash(hasher, expected);
		await Assert.That(stream.Position).IsEqualTo(stream.Length);
	}

	[Test]
	[MatrixDataSource]
	public async Task GetCurrentHashAfterAppendKeepsState([Matrix] bool useAsync)
	{
		byte[] first = CreateDeterministicSource(StreamDrain.BufferSize + 1);
		byte[] second = CreateDeterministicSource(31);
		using HashAlgorithm<Sha256HashAlgorithm> hasher = HashAlgorithm<Sha256HashAlgorithm>.Create();
		using MemoryStream stream = new(first, false);

		if (useAsync)
		{
			await hasher.AppendAsync(stream);
		}
		else
		{
			hasher.Append(stream);
		}

		await AssertCurrentHash(hasher, SHA256.HashData(first));

		hasher.Append(second);

		await AssertCurrentHash(hasher, SHA256.HashData(Concat(first, second)));
	}

	[Test]
	[MatrixDataSource]
	public async Task HashDataSupportsBlake3([Matrix(0, 1023, 1024, 1025, StreamDrain.BufferSize * 3 + 1)] int sourceLength, [Matrix] bool useAsync)
	{
		byte[] source = CreateDeterministicSource(sourceLength);
		byte[] expected = new byte[Blake3HashAlgorithm.HashLength];
		Blake3HashAlgorithm.HashData(source, expected);
		byte[] destination = new byte[Blake3HashAlgorithm.HashLength + 1];
		PrepareDestination(destination);
		using MemoryStream stream = new(source, false);

		int written = useAsync
			? await Blake3HashAlgorithm.HashDataAsync(stream, destination)
			: Blake3HashAlgorithm.HashData(stream, destination);

		await AssertOutput(destination, expected, written);
		await Assert.That(stream.Position).IsEqualTo(stream.Length);
	}

	[Test]
	[MatrixDataSource]
	public async Task AppendRejectsDisposedHasherBeforeReading([Matrix] AppendSourceKind kind, [Matrix] bool useBlake3, [Matrix] bool useAsync)
	{
		using Stream stream = AppendSources.Create(kind);
		long position = stream.Position;

		if (useBlake3)
		{
			await VerifyAppendRejectsDisposed(Blake3HashAlgorithm.Create(), stream, useAsync);
		}
		else
		{
			await VerifyAppendRejectsDisposed(HashAlgorithm<Sha256HashAlgorithm>.Create(), stream, useAsync);
		}

		await Assert.That(stream.Position).IsEqualTo(position);
	}

	[Test]
	[MatrixDataSource]
	public async Task AppendOfEmptyStreamLeavesHashUnchanged([Matrix(AppendSourceKind.NullStream, AppendSourceKind.EmptyStream, AppendSourceKind.StreamAtEnd)] AppendSourceKind kind, [Matrix] bool useAsync)
	{
		byte[] source = CreateDeterministicSource(37);
		byte[] blake3Expected = new byte[Blake3HashAlgorithm.HashLength];
		Blake3HashAlgorithm.HashData(source, blake3Expected);
		using HashAlgorithm<Sha256HashAlgorithm> hasher = HashAlgorithm<Sha256HashAlgorithm>.Create();
		using Blake3HashAlgorithm blake3 = Blake3HashAlgorithm.Create();
		using Stream stream = AppendSources.Create(kind);
		byte[] blake3Actual = new byte[Blake3HashAlgorithm.HashLength];

		hasher.Append(source);
		blake3.Append(source);

		if (useAsync)
		{
			await hasher.AppendAsync(stream);
			await blake3.AppendAsync(stream);
		}
		else
		{
			hasher.Append(stream);
			blake3.Append(stream);
		}

		blake3.GetCurrentHash(blake3Actual);

		await AssertCurrentHash(hasher, SHA256.HashData(source));
		await Assert.That(blake3Actual).IsEquivalentTo(blake3Expected, CollectionOrdering.Matching);
	}

	private static async Task VerifyAppendRejectsDisposed<TAlgorithm>(TAlgorithm hasher, Stream stream, bool useAsync) where TAlgorithm : class, IHashAlgorithm<TAlgorithm>
	{
		hasher.Dispose();

		if (useAsync)
		{
			await Assert.That(() => hasher.AppendAsync(stream).AsTask()).ThrowsExactly<ObjectDisposedException>();
		}
		else
		{
			await Assert.That(() => hasher.Append(stream)).ThrowsExactly<ObjectDisposedException>();
		}
	}

	private static async Task AssertCurrentHash(HashAlgorithm<Sha256HashAlgorithm> hasher, byte[] expected)
	{
		byte[] actual = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength];
		hasher.GetCurrentHash(actual);
		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}
}
