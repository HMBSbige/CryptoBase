using CryptoBase.Hashes;
using CryptoBase.Hashes.Sha256;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class HashUtilsTest
{
	[Test]
	public async Task ComputeHashStartsAtCurrentPosition()
	{
		const int startOffset = 137;
		byte[] source = CreateDeterministicSource(81920 + 257);
		byte[] expected = SHA256.HashData(source.AsSpan(startOffset));
		byte[] destination = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength + 1];
		PrepareDestination(destination);
		using MemoryStream stream = new(source, false);
		stream.Position = startOffset;

		int written = stream.ComputeHash<HashAlgorithm<Sha256HashAlgorithm>>(destination);

		await AssertOutput(destination, expected, written);
		await Assert.That(stream.Position).IsEqualTo(stream.Length);
	}

	[Test]
	public async Task ComputeHashRejectsShortDestinationBeforeReading()
	{
		byte[] source = CreateDeterministicSource(257);
		byte[] destination = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength - 1];
		PrepareDestination(destination);
		using MemoryStream stream = new(source, false);
		stream.Position = 11;

		await Assert.That(() => stream.ComputeHash<HashAlgorithm<Sha256HashAlgorithm>>(destination)).ThrowsExactly<ArgumentOutOfRangeException>();

		await Assert.That(stream.Position).IsEqualTo(11);
		await Assert.That(destination).All(static value => value is DestinationSentinel);
	}

	[Test]
	[Arguments(0)]
	[Arguments(257)]
	public async Task ComputeHashContinuesAfterShortReads(int sourceLength)
	{
		byte[] source = CreateDeterministicSource(sourceLength);
		byte[] expected = SHA256.HashData(source);
		byte[] destination = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength];
		using MemoryStream stream = new ShortReadMemoryStream(source, 7);

		int written = stream.ComputeHash<HashAlgorithm<Sha256HashAlgorithm>>(destination);

		await AssertOutput(destination, expected, written);
		await Assert.That(stream.Position).IsEqualTo(stream.Length);
	}

	[Test]
	public async Task ComputeHashAsyncStartsAtCurrentPosition()
	{
		const int startOffset = 137;
		byte[] source = CreateDeterministicSource(81920 + 257);
		byte[] expected = SHA256.HashData(source.AsSpan(startOffset));
		using MemoryStream stream = new(source, false);
		stream.Position = startOffset;
		byte[] destination = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength + 1];
		PrepareDestination(destination);

		int written = await stream.ComputeHashAsync<HashAlgorithm<Sha256HashAlgorithm>>(destination);

		await AssertOutput(destination, expected, written);
		await Assert.That(stream.Position).IsEqualTo(stream.Length);
	}

	[Test]
	public async Task ComputeHashAsyncRejectsShortDestinationBeforeReading()
	{
		byte[] source = CreateDeterministicSource(257);
		byte[] destination = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength - 1];
		PrepareDestination(destination);
		using MemoryStream stream = new(source, false);
		stream.Position = 11;

		await Assert.That(() => stream.ComputeHashAsync<HashAlgorithm<Sha256HashAlgorithm>>(destination).AsTask()).ThrowsExactly<ArgumentOutOfRangeException>();

		await Assert.That(stream.Position).IsEqualTo(11);
		await Assert.That(destination).All(static value => value is DestinationSentinel);
	}

	[Test]
	public async Task ComputeHashRejectsNullAndUnreadableStreamsBeforeWriting()
	{
		byte[] destination = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength];
		PrepareDestination(destination);

		await Assert.That(() => HashUtils.ComputeHash<HashAlgorithm<Sha256HashAlgorithm>>(null!, destination)).ThrowsExactly<ArgumentNullException>();
		await Assert.That(() => CreateUnreadableStream().ComputeHash<HashAlgorithm<Sha256HashAlgorithm>>(destination)).ThrowsExactly<ArgumentException>();
		await Assert.That(() => HashUtils.ComputeHashAsync<HashAlgorithm<Sha256HashAlgorithm>>(null!, destination).AsTask()).ThrowsExactly<ArgumentNullException>();
		await Assert.That(() => CreateUnreadableStream().ComputeHashAsync<HashAlgorithm<Sha256HashAlgorithm>>(destination).AsTask()).ThrowsExactly<ArgumentException>();
		await Assert.That(destination).All(static value => value is DestinationSentinel);
	}

	[Test]
	public async Task ComputeHashAsyncHonorsPreCanceledTokenBeforeReading()
	{
		byte[] source = CreateDeterministicSource(257);
		byte[] destination = new byte[HashAlgorithm<Sha256HashAlgorithm>.HashLength];
		PrepareDestination(destination);
		using MemoryStream stream = new(source, false);
		using CancellationTokenSource cancellation = new();
		cancellation.Cancel();

		OperationCanceledException exception = (await Assert.That(() => stream.ComputeHashAsync<HashAlgorithm<Sha256HashAlgorithm>>(destination, cancellation.Token).AsTask()).Throws<OperationCanceledException>())!;
		await Assert.That(exception.CancellationToken).IsEqualTo(cancellation.Token);
		await Assert.That(stream.Position).IsZero();
		await Assert.That(destination).All(static value => value is DestinationSentinel);
	}

	private static MemoryStream CreateUnreadableStream()
	{
		MemoryStream stream = new();
		stream.Dispose();
		return stream;
	}

	private sealed class ShortReadMemoryStream(byte[] buffer, int maxReadSize) : MemoryStream(buffer, false)
	{
		public override int Read(byte[] buffer, int offset, int count)
		{
			return base.Read(buffer, offset, Math.Min(count, maxReadSize));
		}

		public override int Read(Span<byte> buffer)
		{
			return base.Read(buffer.Slice(0, Math.Min(buffer.Length, maxReadSize)));
		}
	}
}
