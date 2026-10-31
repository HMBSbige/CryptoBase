using CryptoBase.Ciphers.Aead;
using CryptoBase.IO;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.IO.ChunkedTestUtils;
using static CryptoBase.Tests.IO.StreamTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.IO;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class ChunkedEncryptionStreamTest
{
	// Whether writes split chunks, end on their boundaries or span several, the one-shot decryption, which the vectors check, must recover the message. The writes go through the array overloads; the other tests write spans and memory.
	[Test]
	[MatrixDataSource]
	public async Task DecryptsForAnyWrites([Matrix(0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, 3 * ChunkSize, 3 * ChunkSize + 5)] int length, [Matrix(1, 4099, ChunkSize, ChunkSize + 1, int.MaxValue)] int writeSize, [Matrix] bool useAsync)
	{
		byte[] key = NewKey();
		byte[] plaintext = CreateDeterministicSource(length);
		using MemoryStream inner = useAsync ? new YieldingMemoryStream() : new MemoryStream();

		await using (ChunkedEncryptionStream<Cobblestone128Cipher> stream = ChunkedEncryptionStream.Create<Cobblestone128Cipher>(inner, key, MessageContext, leaveOpen: true))
		{
			for (int offset = 0; offset < length; offset += writeSize)
			{
				await WriteAsync(stream, plaintext, offset, Math.Min(writeSize, length - offset), useAsync);
			}

			await FlushFinalChunkAsync(stream, useAsync);
		}

		using (Assert.Multiple())
		{
			await Assert.That(TryDecrypt(key, inner.ToArray(), out byte[] decrypted)).IsTrue();
			await Assert.That(decrypted).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
		}
	}

	// Nothing reaches the inner stream until a chunk is complete; then the header and the chunk go together.
	[Test]
	public async Task WritesEachChunkOnceItIsComplete()
	{
		using MemoryStream inner = new();
		using ChunkedEncryptionStream<Cobblestone128Cipher> stream = ChunkedEncryptionStream.Create<Cobblestone128Cipher>(inner, NewKey(), MessageContext, leaveOpen: true);
		byte[] data = CreateDeterministicSource(ChunkSize);

		stream.Write(data.AsSpan(0, ChunkSize - 1));
		stream.Flush();
		await Assert.That(inner.Length).IsZero();

		stream.WriteByte(1);
		await Assert.That(inner.Length).IsEqualTo(HeaderSize + EncryptedChunkSize);

		stream.Write(data.AsSpan(0, 100));
		await Assert.That(inner.Length).IsEqualTo(HeaderSize + EncryptedChunkSize);

		stream.FlushFinalChunk();

		using (Assert.Multiple())
		{
			await Assert.That(inner.Length).IsEqualTo(HeaderSize + EncryptedChunkSize + 100 + TagSize);
			await Assert.That(stream.HasFlushedFinalChunk).IsTrue();
		}
	}

	// Disposal without the final chunk must not complete the message, so an abandoned write cannot leave a valid shorter one.
	[Test]
	[MatrixDataSource]
	public async Task DisposalWithoutTheFinalChunkLeavesATruncatedMessage([Matrix(0, 100, ChunkSize, ChunkSize + 100)] int length, [Matrix] bool useAsync)
	{
		byte[] key = NewKey();
		using MemoryStream inner = new();
		ChunkedEncryptionStream<Cobblestone128Cipher> stream = ChunkedEncryptionStream.Create<Cobblestone128Cipher>(inner, key, MessageContext, leaveOpen: true);
		await WriteAsync(stream, CreateDeterministicSource(length), useAsync);
		await DisposeAsync(stream, useAsync);

		using (Assert.Multiple())
		{
			await Assert.That(stream.HasFlushedFinalChunk).IsFalse();
			await Assert.That(inner.Length).IsEqualTo(length < ChunkSize ? 0 : HeaderSize + EncryptedChunkSize);
			await Assert.That(TryDecrypt(key, inner.ToArray(), out _)).IsFalse();
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task NothingCanBeWrittenAfterTheFinalChunk([Matrix] bool useAsync)
	{
		using MemoryStream inner = new();
		using ChunkedEncryptionStream<Cobblestone128Cipher> stream = ChunkedEncryptionStream.Create<Cobblestone128Cipher>(inner, NewKey(), MessageContext, leaveOpen: true);
		await FlushFinalChunkAsync(stream, useAsync);
		long length = inner.Length;

		using (Assert.Multiple())
		{
			await Assert.That(length).IsEqualTo(HeaderSize + TagSize);
			await Assert.That(() => stream.Write([1])).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => stream.Write([])).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => stream.WriteAsync(new byte[1]).AsTask()).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => stream.FlushFinalChunk()).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => stream.FlushFinalChunkAsync().AsTask()).ThrowsExactly<InvalidOperationException>();
			await Assert.That(inner.Length).IsEqualTo(length);
		}
	}

	// After a failed write the ciphertext is in an unknown state, so the stream refuses to go on, even with writes that would only buffer.
	[Test]
	[MatrixDataSource]
	public async Task AFailedInnerWriteEndsTheMessage([Matrix] bool useAsync)
	{
		byte[] key = NewKey();
		using FailingWriteMemoryStream inner = new(1);
		ChunkedEncryptionStream<LimitedChunkCipher> stream = ChunkedEncryptionStream.Create<LimitedChunkCipher>(inner, key, MessageContext, leaveOpen: true);
		await WriteAsync(stream, CreateDeterministicSource(ChunkSize + 1), useAsync);
		await Assert.That(() => WriteAsync(stream, CreateDeterministicSource(ChunkSize), useAsync)).ThrowsExactly<IOException>();
		long length = inner.Length;

		using (Assert.Multiple())
		{
			await Assert.That(() => stream.Write([1])).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => stream.WriteAsync(new byte[1]).AsTask()).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => stream.FlushFinalChunk()).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => stream.FlushFinalChunkAsync().AsTask()).ThrowsExactly<InvalidOperationException>();
		}

		await DisposeAsync(stream, useAsync);

		using (Assert.Multiple())
		{
			await Assert.That(inner.Length).IsEqualTo(length);
			await Assert.That(LimitedChunkCipher.GetLiveInstances(key)).IsZero();
		}
	}

	// LimitedChunkCipher allows three chunks, so a message of at most 3 * ChunkSize - 1 bytes. A write that would pass that fails before it takes anything, and the stream stays usable.
	[Test]
	[MatrixDataSource]
	public async Task MessagesCannotExceedTheChunkLimit([Matrix] bool useAsync)
	{
		byte[] key = NewKey();
		byte[] plaintext = CreateDeterministicSource((int)LimitedChunkCipher.MaxMessageLength);
		using MemoryStream inner = new();

		await using (ChunkedEncryptionStream<LimitedChunkCipher> stream = ChunkedEncryptionStream.Create<LimitedChunkCipher>(inner, key, MessageContext, leaveOpen: true))
		{
			await Assert.That(() => WriteAsync(stream, new byte[plaintext.Length + 1], useAsync)).ThrowsExactly<IOException>();
			await WriteAsync(stream, plaintext.AsMemory(0, 100), useAsync);
			await WriteAsync(stream, plaintext.AsMemory(100), useAsync);
			long length = inner.Length;
			await Assert.That(() => WriteAsync(stream, new byte[1], useAsync)).ThrowsExactly<IOException>();
			await Assert.That(inner.Length).IsEqualTo(length);
			await FlushFinalChunkAsync(stream, useAsync);
		}

		using (Assert.Multiple())
		{
			await Assert.That(TryDecrypt(key, inner.ToArray(), out byte[] decrypted)).IsTrue();
			await Assert.That(decrypted).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task DisposalReleasesTheCipherAndHonorsLeaveOpen([Matrix] bool leaveOpen, [Matrix] bool useAsync)
	{
		byte[] key = NewKey();
		using MemoryStream inner = new();
		ChunkedEncryptionStream<LimitedChunkCipher> stream = ChunkedEncryptionStream.Create<LimitedChunkCipher>(inner, key, MessageContext, leaveOpen);
		await Assert.That(LimitedChunkCipher.GetLiveInstances(key)).IsEqualTo(1);
		stream.Write([1, 2, 3]);
		await DisposeAsync(stream, useAsync);
		await DisposeAsync(stream, useAsync);

		using (Assert.Multiple())
		{
			await Assert.That(LimitedChunkCipher.GetLiveInstances(key)).IsZero();
			await Assert.That(inner.CanWrite).IsEqualTo(leaveOpen);
			await Assert.That(stream.CanWrite).IsFalse();
			await Assert.That(() => stream.Write([1])).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => stream.WriteAsync(new byte[1]).AsTask()).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => stream.FlushFinalChunk()).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => stream.Flush()).ThrowsExactly<ObjectDisposedException>();
		}
	}

	[Test]
	public async Task MembersFollowStreamConventions()
	{
		byte[] key = NewKey();
		using MemoryStream inner = new();
		using ChunkedEncryptionStream<Cobblestone128Cipher> stream = ChunkedEncryptionStream.Create<Cobblestone128Cipher>(inner, key, MessageContext, leaveOpen: true);
		using CancellationTokenSource cancellation = new();
		await cancellation.CancelAsync();

		using (Assert.Multiple())
		{
			await Assert.That(stream.CanRead).IsFalse();
			await Assert.That(stream.CanSeek).IsFalse();
			await Assert.That(stream.CanWrite).IsTrue();
			await Assert.That(() => stream.Length).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => stream.Position).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => stream.Position = 0).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => stream.Seek(0, SeekOrigin.Begin)).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => stream.SetLength(0)).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => stream.Read(new byte[1], 0, 1)).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => stream.WriteAsync(new byte[ChunkSize], cancellation.Token).AsTask()).Throws<OperationCanceledException>();
			await Assert.That(() => stream.FlushFinalChunkAsync(cancellation.Token).AsTask()).Throws<OperationCanceledException>();
			await Assert.That(() => ChunkedEncryptionStream.Create<Cobblestone128Cipher>(null!, key)).ThrowsExactly<ArgumentNullException>().WithParameterName("inner");
			await Assert.That(() => ChunkedEncryptionStream.Create<Cobblestone128Cipher>(new MemoryStream([], false), key)).ThrowsExactly<ArgumentException>().WithParameterName("inner");
			await Assert.That(() => ChunkedEncryptionStream.Create<Cobblestone128Cipher>(inner, key.AsSpan(1))).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("key");
			await Assert.That(() => ChunkedEncryptionStream.Create<Cobblestone256Cipher>(inner, key)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("key");
		}

		// The cancelled calls changed nothing.
		stream.FlushFinalChunk();
		await Assert.That(TryDecrypt(key, inner.ToArray(), out byte[] decrypted)).IsTrue();
		await Assert.That(decrypted).IsEmpty();
	}
}
