using CryptoBase.Ciphers.Aead;
using CryptoBase.IO;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using static CryptoBase.Tests.IO.ChunkedTestUtils;
using static CryptoBase.Tests.IO.StreamTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.IO;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class ChunkedDecryptionStreamTest
{
	// Two full chunks and a short one.
	private const int MessageLength = 2 * ChunkSize + 5;

	// The inner stream returns at most 1000 bytes per read, so the stream gathers each chunk from several reads, whatever the caller asks for.
	[Test]
	[MatrixDataSource]
	public async Task DecryptsWithAnyReadSizes([Matrix(0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, 3 * ChunkSize, 3 * ChunkSize + 5)] int length, [Matrix(1, 4099, ChunkSize, ChunkSize + 1, 100000)] int readSize, [Matrix] bool useAsync)
	{
		byte[] key = NewKey();
		byte[] plaintext = CreateDeterministicSource(length);
		using MemoryStream inner = useAsync ? new YieldingMemoryStream(Encrypt(key, plaintext), 1000) : new LimitedReadMemoryStream(Encrypt(key, plaintext), 1000);
		await using ChunkedDecryptionStream<Cobblestone128Cipher> stream = await CreateAsync(inner, key, useAsync);

		(byte[] output, Exception? failure) = await ReadUntilEndOrFailure(stream, [readSize], useAsync);

		using (Assert.Multiple())
		{
			await Assert.That(failure).IsNull();
			await XtsTestUtils.AssertBytesEqual(output, plaintext);

			// The end stays the end.
			await Assert.That(stream.Read(new byte[10])).IsZero();
			await Assert.That(await stream.ReadAsync(new byte[10])).IsZero();
			await Assert.That(stream.ReadByte()).IsEqualTo(-1);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task ReadsWholeStreamsWithStreamHelpers([Matrix] bool useAsync)
	{
		byte[] key = NewKey();
		byte[] plaintext = CreateDeterministicSource(MessageLength);
		using MemoryStream inner = new(Encrypt(key, plaintext));
		await using ChunkedDecryptionStream<Cobblestone128Cipher> stream = await CreateAsync(inner, key, useAsync);
		using MemoryStream output = new();

		await CopyToAsync(stream, output, useAsync);

		await XtsTestUtils.AssertBytesEqual(output.ToArray(), plaintext);
	}

	// Each case gives the ciphertext length and the plaintext that may come out before the error: the chunks that authenticate.
	[Test]
	[MatrixDataSource]
	public async Task TruncationFailsAfterTheIntactChunks([Matrix(HeaderSize, HeaderSize + TagSize - 1, HeaderSize + EncryptedChunkSize, HeaderSize + EncryptedChunkSize + 1000, HeaderSize + 2 * EncryptedChunkSize, HeaderSize + 2 * EncryptedChunkSize + TagSize + 4)] int length, [Matrix] bool useAsync)
	{
		byte[] key = NewKey();
		byte[] plaintext = CreateDeterministicSource(MessageLength);
		byte[] ciphertext = Encrypt(key, plaintext);
		int intactChunks = (length - HeaderSize) / EncryptedChunkSize;
		using MemoryStream inner = new(ciphertext, 0, length);

		await AssertFailsAfter(inner, key, plaintext.AsSpan(0, intactChunks * ChunkSize).ToArray(), useAsync);
	}

	// An empty read returns zero without reading on, so it does not mark the end: the damaged empty last chunk is found only by a non-empty read.
	[Test]
	[MatrixDataSource]
	public async Task EmptyReadsDoNotMarkTheEnd([Matrix] bool useAsync)
	{
		byte[] key = NewKey();
		byte[] ciphertext = Encrypt(key, CreateDeterministicSource(ChunkSize));
		await using ChunkedDecryptionStream<Cobblestone128Cipher> stream = await CreateAsync(new MemoryStream(Flip(ciphertext, ciphertext.Length - 1)), key, useAsync);
		byte[] buffer = new byte[ChunkSize];

		int read = useAsync ? await stream.ReadAsync(buffer) : stream.Read(buffer);
		int emptyRead = useAsync ? await stream.ReadAsync(Memory<byte>.Empty) : stream.Read(buffer, 0, 0);

		using (Assert.Multiple())
		{
			await Assert.That(read).IsEqualTo(ChunkSize);
			await Assert.That(emptyRead).IsZero();
		}

		if (useAsync)
		{
			await Assert.That(() => stream.ReadAsync(buffer).AsTask()).ThrowsExactly<AuthenticationTagMismatchException>();
		}
		else
		{
			await Assert.That(() => stream.Read(buffer)).ThrowsExactly<AuthenticationTagMismatchException>();
		}
	}

	public static IEnumerable<Func<DamageCase>> DamagedMessages()
	{
		yield return () => new DamageCase("chunks 0 and 1 swapped", static ciphertext => SwapChunks(ciphertext, 0, 1), 0);
		yield return () => new DamageCase("chunk 0 in place of chunk 1", static ciphertext => [.. ciphertext.AsSpan(0, GetChunkOffset(1)), .. ciphertext.AsSpan(GetChunkOffset(0), EncryptedChunkSize), .. ciphertext.AsSpan(GetChunkOffset(2))], ChunkSize);
		yield return () => new DamageCase("chunk 0 body modified", static ciphertext => Flip(ciphertext, GetChunkOffset(0) + 100), 0);
		yield return () => new DamageCase("chunk 1 tag modified", static ciphertext => Flip(ciphertext, GetChunkOffset(2) - 1), ChunkSize);
		yield return () => new DamageCase("last chunk modified", static ciphertext => Flip(ciphertext, ciphertext.Length - 1), 2 * ChunkSize);
		yield return () => new DamageCase("one byte appended", static ciphertext => [.. ciphertext, 0], 2 * ChunkSize);
		yield return () => new DamageCase("a tag-sized tail appended", static ciphertext => [.. ciphertext, .. ciphertext.AsSpan(ciphertext.Length - TagSize, TagSize)], 2 * ChunkSize);
	}

	[Test]
	[MethodDataSource(nameof(DamagedMessages))]
	public async Task ModifiedReorderedOrExtendedMessagesFail(DamageCase scenario)
	{
		byte[] key = NewKey();
		byte[] plaintext = CreateDeterministicSource(MessageLength);
		byte[] damaged = scenario.Damage(Encrypt(key, plaintext));

		foreach (bool useAsync in (bool[])[false, true])
		{
			using MemoryStream inner = new(damaged);
			await AssertFailsAfter(inner, key, plaintext.AsSpan(0, scenario.IntactLength).ToArray(), useAsync);
		}
	}

	// The header is checked before the stream exists, so no chunk is ever decrypted with another key or context.
	[Test]
	[MatrixDataSource]
	public async Task CreationChecksTheHeader([Matrix] bool useAsync)
	{
		byte[] key = NewKey();
		byte[] ciphertext = Encrypt(key, CreateDeterministicSource(100));

		foreach ((byte[] candidateKey, byte[] context, byte[] candidate) in ((byte[], byte[], byte[])[])[(NewKey(), MessageContext, ciphertext), (key, [], ciphertext), (key, MessageContext, Flip(ciphertext, 0)), (key, MessageContext, Flip(ciphertext, HeaderSize - 1)), (key, MessageContext, ciphertext.AsSpan(0, HeaderSize - 1).ToArray())])
		{
			using MemoryStream inner = new(candidate);
			await Assert.That(() => (Task)CreateDecryptionStreamAsync<Cobblestone128Cipher>(inner, candidateKey, context, useAsync)).ThrowsExactly<AuthenticationTagMismatchException>();
			await Assert.That(inner.CanRead).IsTrue();
		}
	}

	// LimitedChunkCipher allows three chunks, and a message of 3 * ChunkSize bytes has four: three full ones and an empty one.
	[Test]
	[MatrixDataSource]
	public async Task MessagesCannotExceedTheChunkLimit([Matrix] bool useAsync)
	{
		byte[] key = NewKey();
		byte[] largest = CreateDeterministicSource((int)LimitedChunkCipher.MaxMessageLength);
		byte[] tooLong = CreateDeterministicSource((int)LimitedChunkCipher.MaxMessageLength + 1);

		await using (ChunkedDecryptionStream<LimitedChunkCipher> stream = await CreateDecryptionStreamAsync<LimitedChunkCipher>(new MemoryStream(Encrypt(key, largest)), key, MessageContext, useAsync))
		{
			(byte[] output, Exception? failure) = await ReadUntilEndOrFailure(stream, [5000], useAsync);
			await Assert.That(failure).IsNull();
			await XtsTestUtils.AssertBytesEqual(output, largest);
		}

		await using (ChunkedDecryptionStream<LimitedChunkCipher> stream = await CreateDecryptionStreamAsync<LimitedChunkCipher>(new MemoryStream(Encrypt(key, tooLong)), key, MessageContext, useAsync))
		{
			(byte[] output, Exception? failure) = await ReadUntilEndOrFailure(stream, [5000], useAsync);
			await Assert.That(failure).IsTypeOf<AuthenticationTagMismatchException>();
			await XtsTestUtils.AssertBytesEqual(output, tooLong);
			await AssertKeepsFailing(stream);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task DisposalReleasesTheCipherAndHonorsLeaveOpen([Matrix] bool leaveOpen, [Matrix] bool useAsync)
	{
		byte[] key = NewKey();
		using MemoryStream inner = new(Encrypt(key, CreateDeterministicSource(MessageLength)));
		ChunkedDecryptionStream<LimitedChunkCipher> stream = await CreateDecryptionStreamAsync<LimitedChunkCipher>(inner, key, MessageContext, useAsync, leaveOpen);
		await Assert.That(LimitedChunkCipher.GetLiveInstances(key)).IsEqualTo(1);
		await Assert.That(stream.Read(new byte[10])).IsEqualTo(10);
		await DisposeAsync(stream, useAsync);
		await DisposeAsync(stream, useAsync);

		using (Assert.Multiple())
		{
			await Assert.That(LimitedChunkCipher.GetLiveInstances(key)).IsZero();
			await Assert.That(inner.CanRead).IsEqualTo(leaveOpen);
			await Assert.That(stream.CanRead).IsFalse();
			await Assert.That(() => stream.Read(new byte[1])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => stream.ReadAsync(new byte[1]).AsTask()).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => stream.Flush()).ThrowsExactly<ObjectDisposedException>();
		}
	}

	[Test]
	public async Task MembersFollowStreamConventions()
	{
		byte[] key = NewKey();
		using MemoryStream inner = new(Encrypt(key, CreateDeterministicSource(10)));
		using ChunkedDecryptionStream<Cobblestone128Cipher> stream = ChunkedDecryptionStream.Create<Cobblestone128Cipher>(inner, key, MessageContext, leaveOpen: true);
		using CancellationTokenSource cancellation = new();
		await cancellation.CancelAsync();

		using (Assert.Multiple())
		{
			await Assert.That(stream.CanRead).IsTrue();
			await Assert.That(stream.CanSeek).IsFalse();
			await Assert.That(stream.CanWrite).IsFalse();
			await Assert.That(() => stream.Length).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => stream.Position).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => stream.Position = 0).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => stream.Seek(0, SeekOrigin.Begin)).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => stream.SetLength(0)).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => stream.Write([1], 0, 1)).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => stream.ReadAsync(new byte[1], cancellation.Token).AsTask()).Throws<OperationCanceledException>();
			await Assert.That(() => (Task)ChunkedDecryptionStream.CreateAsync<Cobblestone128Cipher>(new MemoryStream(), key, cancellationToken: cancellation.Token)).Throws<OperationCanceledException>();
			await Assert.That(() => ChunkedDecryptionStream.Create<Cobblestone128Cipher>(null!, key)).ThrowsExactly<ArgumentNullException>().WithParameterName("inner");
			await Assert.That(() => ChunkedDecryptionStream.Create<Cobblestone128Cipher>(new WriteOnlyMemoryStream(), key)).ThrowsExactly<ArgumentException>().WithParameterName("inner");
			await Assert.That(() => ChunkedDecryptionStream.Create<Cobblestone128Cipher>(inner, key.AsSpan(1))).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("key");
			await Assert.That(() => (Task)ChunkedDecryptionStream.CreateAsync<Cobblestone128Cipher>(inner, key.AsMemory(1))).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("key");
		}

		// Flush does nothing on a read-only stream, and the failed calls changed nothing.
		stream.Flush();
		await Assert.That(stream.Read(new byte[20])).IsEqualTo(10);
	}

	/// <summary>Checks that the stream returns <paramref name="intact" /> and then fails for good, with each read size and both read paths.</summary>
	private static async Task AssertFailsAfter(MemoryStream inner, byte[] key, byte[] intact, bool useAsync)
	{
		foreach (int readSize in (int[])[1, 4099, ChunkSize, 100000])
		{
			inner.Position = 0;

			if (inner.Length < HeaderSize)
			{
				await Assert.That(() => (Task)CreateAsync(inner, key, useAsync)).ThrowsExactly<AuthenticationTagMismatchException>();
				return;
			}

			await using ChunkedDecryptionStream<Cobblestone128Cipher> stream = await CreateAsync(inner, key, useAsync);
			(byte[] output, Exception? failure) = await ReadUntilEndOrFailure(stream, [readSize], useAsync);

			await Assert.That(failure).IsTypeOf<AuthenticationTagMismatchException>();
			await XtsTestUtils.AssertBytesEqual(output, intact);
			await AssertKeepsFailing(stream);
		}
	}

	private static Task<ChunkedDecryptionStream<Cobblestone128Cipher>> CreateAsync(Stream inner, byte[] key, bool useAsync)
	{
		return CreateDecryptionStreamAsync<Cobblestone128Cipher>(inner, key, MessageContext, useAsync);
	}
}

/// <summary>A way to damage an encrypted message, and how much plaintext authenticates before the damage.</summary>
public sealed record DamageCase(string Name, Func<byte[], byte[]> Damage, int IntactLength)
{
	public override string ToString()
	{
		return Name;
	}
}
