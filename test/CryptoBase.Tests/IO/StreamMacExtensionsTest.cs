using CryptoBase.Abstractions.Macs;
using CryptoBase.IO;
using CryptoBase.Tests.Wycheproof;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;
using HmacSha256 = CryptoBase.Macs.Hmac.HmacAlgorithm<CryptoBase.Hashes.Sha256.Sha256HashAlgorithm>;
using HmacSha512 = CryptoBase.Macs.Hmac.HmacAlgorithm<CryptoBase.Hashes.Sha512.Sha512HashAlgorithm>;

namespace CryptoBase.Tests.IO;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class StreamMacExtensionsTest
{
	private static readonly byte[] Key = CreateDeterministicSource(32);

	[Test]
	[MatrixDataSource]
	public async Task MacDataStartsAtCurrentPosition([Matrix(0, 32, 131)] int keyLength, [Matrix] bool useAsync)
	{
		const int startOffset = 137;
		byte[] key = CreateDeterministicSource(keyLength);
		byte[] source = CreateDeterministicSource(StreamDrain.BufferSize * 2 + 257);
		byte[] expected = HMACSHA256.HashData(key, source.AsSpan(startOffset));
		byte[] destination = new byte[HmacSha256.MacLength + 1];
		PrepareDestination(destination);
		using MemoryStream stream = new(source, false);
		stream.Position = startOffset;

		int written = useAsync
			? await HmacSha256.MacDataAsync(key, stream, destination)
			: HmacSha256.MacData(key, stream, destination);

		await AssertOutput(destination, expected, written);
		await Assert.That(stream.Position).IsEqualTo(stream.Length);
	}

	[Test]
	[MatrixDataSource]
	public async Task MacDataRejectsShortDestinationBeforeReading([Matrix] bool useAsync)
	{
		byte[] source = CreateDeterministicSource(257);
		byte[] destination = new byte[TrackingMac.MacLength - 1];
		PrepareDestination(destination);
		using MemoryStream stream = new(source, false);
		stream.Position = 11;
		List<TrackingMac> created = TrackingMac.Track();

		using (Assert.Multiple())
		{
			if (useAsync)
			{
				await Assert.That(() => TrackingMac.MacDataAsync(Key, stream, destination).AsTask()).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
			}
			else
			{
				await Assert.That(() => TrackingMac.MacData(Key, stream, destination)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
			}
			await Assert.That(stream.Position).IsEqualTo(11);
			await Assert.That(destination).All(static value => value is DestinationSentinel);
			await Assert.That(created).IsEmpty();
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task MacDataContinuesAfterShortReads([Matrix(0, 257)] int sourceLength, [Matrix] bool useAsync)
	{
		byte[] source = CreateDeterministicSource(sourceLength);
		byte[] expected = HMACSHA256.HashData(Key, source);
		byte[] destination = new byte[HmacSha256.MacLength];
		using MemoryStream stream = new YieldingMemoryStream(source, 7);

		int written = useAsync
			? await HmacSha256.MacDataAsync(Key, stream, destination)
			: HmacSha256.MacData(Key, stream, destination);

		await AssertOutput(destination, expected, written);
		await Assert.That(stream.Position).IsEqualTo(stream.Length);
	}

	[Test]
	public async Task MacDataAsyncConsumesKeyBeforeReturning()
	{
		byte[] key = CreateDeterministicSource(97);
		byte[] source = CreateDeterministicSource(4099);
		byte[] expected = HMACSHA256.HashData(key, source);
		byte[] destination = new byte[HmacSha256.MacLength];
		using YieldingMemoryStream stream = new(source, 1000);

		ValueTask<int> pending = HmacSha256.MacDataAsync(key, stream, destination);
		key.AsSpan().Clear();
		int written = await pending;

		await AssertOutput(destination, expected, written);
	}

	[Test]
	public async Task MacDataRejectsNullAndUnreadableStreamsBeforeWriting()
	{
		byte[] destination = new byte[HmacSha256.MacLength];
		PrepareDestination(destination);

		using (Assert.Multiple())
		{
			await Assert.That(() => HmacSha256.MacData(Key, null!, destination)).ThrowsExactly<ArgumentNullException>().WithParameterName("source");
			await Assert.That(() => HmacSha256.MacData(Key, new WriteOnlyMemoryStream(), destination)).ThrowsExactly<ArgumentException>().WithParameterName("source");
			await Assert.That(() => HmacSha256.MacDataAsync(Key, null!, destination).AsTask()).ThrowsExactly<ArgumentNullException>().WithParameterName("source");
			await Assert.That(() => HmacSha256.MacDataAsync(Key, new WriteOnlyMemoryStream(), destination).AsTask()).ThrowsExactly<ArgumentException>().WithParameterName("source");
			await Assert.That(destination).All(static value => value is DestinationSentinel);
		}
	}

	[Test]
	public async Task AppendRejectsNullArgumentsAndUnreadableStreams()
	{
		using HmacSha256 mac = HmacSha256.Create(Key);
		HmacSha256? nullMac = null;
		using MemoryStream stream = new(CreateDeterministicSource(257), false);
		stream.Position = 11;

		using (Assert.Multiple())
		{
			await Assert.That(() => nullMac!.Append(stream)).ThrowsExactly<ArgumentNullException>().WithParameterName("mac");
			await Assert.That(() => nullMac!.AppendAsync(stream).AsTask()).ThrowsExactly<ArgumentNullException>().WithParameterName("mac");
			await Assert.That(() => mac.Append((Stream)null!)).ThrowsExactly<ArgumentNullException>().WithParameterName("source");
			await Assert.That(() => mac.AppendAsync(null!).AsTask()).ThrowsExactly<ArgumentNullException>().WithParameterName("source");
			await Assert.That(() => mac.Append(new WriteOnlyMemoryStream())).ThrowsExactly<ArgumentException>().WithParameterName("source");
			await Assert.That(() => mac.AppendAsync(new WriteOnlyMemoryStream()).AsTask()).ThrowsExactly<ArgumentException>().WithParameterName("source");
			await Assert.That(stream.Position).IsEqualTo(11);
			await AssertCurrentMac(mac, HMACSHA256.HashData(Key, ReadOnlySpan<byte>.Empty));
		}
	}

	[Test]
	public async Task MacDataAsyncHonorsPreCanceledTokenBeforeReading()
	{
		byte[] source = CreateDeterministicSource(257);
		byte[] destination = new byte[TrackingMac.MacLength];
		PrepareDestination(destination);
		using MemoryStream stream = new(source, false);
		using CancellationTokenSource cancellation = new();
		cancellation.Cancel();
		List<TrackingMac> created = TrackingMac.Track();

		OperationCanceledException exception = (await Assert.That(() => TrackingMac.MacDataAsync(Key, stream, destination, cancellation.Token).AsTask()).Throws<OperationCanceledException>())!;

		using (Assert.Multiple())
		{
			await Assert.That(exception.CancellationToken).IsEqualTo(cancellation.Token);
			await Assert.That(stream.Position).IsZero();
			await Assert.That(destination).All(static value => value is DestinationSentinel);
			await Assert.That(created).IsEmpty();
		}
	}

	[Test]
	public async Task AppendAsyncHonorsPreCanceledTokenBeforeReading()
	{
		using HmacSha256 mac = HmacSha256.Create(Key);
		using MemoryStream stream = new(CreateDeterministicSource(257), false);
		using CancellationTokenSource cancellation = new();
		cancellation.Cancel();

		OperationCanceledException exception = (await Assert.That(() => mac.AppendAsync(stream, cancellation.Token).AsTask()).Throws<OperationCanceledException>())!;

		using (Assert.Multiple())
		{
			await Assert.That(exception.CancellationToken).IsEqualTo(cancellation.Token);
			await Assert.That(stream.Position).IsZero();
			await AssertCurrentMac(mac, HMACSHA256.HashData(Key, ReadOnlySpan<byte>.Empty));
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task MacDataDisposesTheInstance([Matrix] bool readFails, [Matrix] bool useAsync)
	{
		byte[] destination = new byte[TrackingMac.MacLength];
		PrepareDestination(destination);
		using MemoryStream stream = readFails ? new FailingReadMemoryStream() : new MemoryStream(CreateDeterministicSource(257), false);
		List<TrackingMac> created = TrackingMac.Track();

		if (readFails)
		{
			if (useAsync)
			{
				await Assert.That(() => TrackingMac.MacDataAsync(Key, stream, destination).AsTask()).ThrowsExactly<IOException>();
			}
			else
			{
				await Assert.That(() => TrackingMac.MacData(Key, stream, destination)).ThrowsExactly<IOException>();
			}
		}
		else if (useAsync)
		{
			await TrackingMac.MacDataAsync(Key, stream, destination);
		}
		else
		{
			TrackingMac.MacData(Key, stream, destination);
		}

		using (Assert.Multiple())
		{
			await Assert.That(created).Count().IsEqualTo(1);
			await Assert.That(created).All(static mac => mac.IsDisposed);
			await Assert.That(destination.All(static value => value is DestinationSentinel)).IsEqualTo(readFails);
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
		byte[] expected = HMACSHA256.HashData(Key, Concat(Concat(header, body.AsSpan(startOffset)), trailer));
		using HmacSha256 mac = HmacSha256.Create(Key);
		using MemoryStream stream = new LimitedReadMemoryStream(body, 1000);
		stream.Position = startOffset;

		mac.Append(header);
		await AppendAsync(mac, stream, useAsync);
		mac.Append(trailer);

		await AssertCurrentMac(mac, expected);
		await Assert.That(stream.Position).IsEqualTo(stream.Length);
	}

	[Test]
	[MatrixDataSource]
	public async Task GetMacAndResetAfterAppendKeepsTheKey([Matrix] bool useAsync)
	{
		byte[] first = CreateDeterministicSource(StreamDrain.BufferSize + 1);
		byte[] second = CreateDeterministicSource(31);
		using HmacSha256 mac = HmacSha256.Create(Key);
		using MemoryStream firstStream = new(first, false);
		using MemoryStream secondStream = new(second, false);
		byte[] firstMac = new byte[HmacSha256.MacLength];

		await AppendAsync(mac, firstStream, useAsync);
		mac.GetMacAndReset(firstMac);
		await AppendAsync(mac, secondStream, useAsync);

		await Assert.That(firstMac).IsEquivalentTo(HMACSHA256.HashData(Key, first), CollectionOrdering.Matching);
		await AssertCurrentMac(mac, HMACSHA256.HashData(Key, second));
	}

	[Test]
	[MatrixDataSource]
	public async Task MacDataSupportsHmacSha512([Matrix(0, 127, 128, 129, StreamDrain.BufferSize * 3 + 1)] int sourceLength, [Matrix] bool useAsync)
	{
		byte[] key = CreateDeterministicSource(64);
		byte[] source = CreateDeterministicSource(sourceLength);
		byte[] expected = HMACSHA512.HashData(key, source);
		byte[] destination = new byte[HmacSha512.MacLength + 1];
		PrepareDestination(destination);
		using MemoryStream stream = new(source, false);

		int written = useAsync
			? await HmacSha512.MacDataAsync(key, stream, destination)
			: HmacSha512.MacData(key, stream, destination);

		await AssertOutput(destination, expected, written);
		await Assert.That(stream.Position).IsEqualTo(stream.Length);
	}

	// Truncated tags are checked as a prefix of the full MAC, as in WycheproofHmacTest.
	[Test]
	[MethodDataSource(typeof(WycheproofHmacTest), nameof(WycheproofHmacTest.Vectors), Arguments = ["hmac_sha256_test.json"])]
	public async Task StreamsMatchWycheproofHmacSha256(MacTestVector vector)
	{
		byte[] mac = new byte[HmacSha256.MacLength];
		byte[] asyncMac = new byte[HmacSha256.MacLength];
		byte[] streamMac = new byte[HmacSha256.MacLength];
		using MemoryStream source = new(vector.Msg, false);

		HmacSha256.MacData(vector.Key, source, mac);
		source.Position = 0;
		await HmacSha256.MacDataAsync(vector.Key, source, asyncMac);

		using (MacStream<HmacSha256> authenticating = MacStream.Create(Stream.Null, HmacSha256.Create(vector.Key)))
		{
			authenticating.Write(vector.Msg);
			authenticating.GetMacAndReset(streamMac);
		}

		using (Assert.Multiple())
		{
			await Assert.That(asyncMac).IsEquivalentTo(mac, CollectionOrdering.Matching);
			await Assert.That(streamMac).IsEquivalentTo(mac, CollectionOrdering.Matching);
			await Assert.That(mac.StartsWith(vector.Tag)).IsEqualTo(vector.Result is WycheproofResult.Valid);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task AppendRejectsDisposedMacBeforeReading([Matrix] AppendSourceKind kind, [Matrix] bool useAsync)
	{
		using Stream stream = AppendSources.Create(kind);
		long position = stream.Position;
		HmacSha256 mac = HmacSha256.Create(Key);
		mac.Dispose();

		if (useAsync)
		{
			await Assert.That(() => mac.AppendAsync(stream).AsTask()).ThrowsExactly<ObjectDisposedException>();
		}
		else
		{
			await Assert.That(() => mac.Append(stream)).ThrowsExactly<ObjectDisposedException>();
		}

		await Assert.That(stream.Position).IsEqualTo(position);
	}

	[Test]
	[MatrixDataSource]
	public async Task AppendOfEmptyStreamLeavesMacUnchanged([Matrix(AppendSourceKind.NullStream, AppendSourceKind.EmptyStream, AppendSourceKind.StreamAtEnd)] AppendSourceKind kind, [Matrix] bool useAsync)
	{
		byte[] source = CreateDeterministicSource(37);
		using HmacSha256 mac = HmacSha256.Create(Key);
		using Stream stream = AppendSources.Create(kind);

		mac.Append(source);
		await AppendAsync(mac, stream, useAsync);

		await AssertCurrentMac(mac, HMACSHA256.HashData(Key, source));
	}

	private static async Task AppendAsync<TAlgorithm>(TAlgorithm mac, Stream stream, bool useAsync) where TAlgorithm : class, IMacAlgorithm<TAlgorithm>
	{
		if (useAsync)
		{
			await mac.AppendAsync(stream);
		}
		else
		{
			mac.Append(stream);
		}
	}

	private static async Task AssertCurrentMac(HmacSha256 mac, byte[] expected)
	{
		byte[] actual = new byte[HmacSha256.MacLength];
		mac.GetCurrentMac(actual);
		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	/// <summary>An HMAC-SHA256 wrapper that records the instances created on the current asynchronous flow.</summary>
	private sealed class TrackingMac : IMacAlgorithm<TrackingMac>
	{
		private static readonly AsyncLocal<List<TrackingMac>?> Created = new();

		private readonly HmacSha256 _inner;

		private TrackingMac(HmacSha256 inner)
		{
			_inner = inner;
		}

		public static int MacLength => HmacSha256.MacLength;

		public bool IsDisposed { get; private set; }

		public static List<TrackingMac> Track()
		{
			List<TrackingMac> created = [];
			Created.Value = created;
			return created;
		}

		public static TrackingMac Create(ReadOnlySpan<byte> key)
		{
			TrackingMac mac = new(HmacSha256.Create(key));
			Created.Value?.Add(mac);
			return mac;
		}

		public static int Mac(ReadOnlySpan<byte> key, ReadOnlySpan<byte> source, Span<byte> destination)
		{
			return HmacSha256.Mac(key, source, destination);
		}

		public void Append(ReadOnlySpan<byte> source)
		{
			_inner.Append(source);
		}

		public void Reset()
		{
			_inner.Reset();
		}

		public int GetCurrentMac(Span<byte> destination)
		{
			return _inner.GetCurrentMac(destination);
		}

		public int GetMacAndReset(Span<byte> destination)
		{
			return _inner.GetMacAndReset(destination);
		}

		public void Dispose()
		{
			IsDisposed = true;
			_inner.Dispose();
		}
	}
}
