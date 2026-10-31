using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Aead;
using CryptoBase.IO;
using Microsoft.Win32.SafeHandles;
using System.Diagnostics.CodeAnalysis;
using System.IO.Compression;
using System.Security.Cryptography;
using static CryptoBase.Tests.IO.ChunkedTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.IO;

public enum ChunkedStorageKind
{
	Stream,
	FileHandle
}

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class ChunkedRandomAccessTest
{
	// Three full chunks and a short one.
	private const int MessageLength = 3 * ChunkSize + 100;

	[Test]
	[MatrixDataSource]
	public async Task ReadsMatchThePlaintextAtAnyOffset([Matrix] ChunkedStorageKind kind, [Matrix] bool useAsync)
	{
		byte[] key = NewKey();
		byte[] plaintext = CreateDeterministicSource(MessageLength);
		using ChunkedStorage storage = new(kind, Encrypt(key, plaintext), useAsync);
		using ChunkedRandomAccess<Cobblestone128Cipher> access = await storage.OpenAsync<Cobblestone128Cipher>(key, MessageContext, useAsync);
		await Assert.That(access.Length).IsEqualTo(MessageLength);
		Random random = new(0x5EED);

		for (int i = 0; i < 300; ++i)
		{
			long offset = random.Next(4) switch
			{
				0 => random.Next(5) * ChunkSize,
				1 => random.Next(MessageLength - 10, MessageLength + 10),
				_ => random.Next(MessageLength)
			};
			int count = random.Next(4) switch
			{
				0 => random.Next(20),
				1 => random.Next(ChunkSize - 10, ChunkSize + 10),
				2 => random.Next(3 * ChunkSize),
				_ => random.Next(2 * MessageLength)
			};
			int index = random.Next(8);
			byte[] buffer = CreateGuardedBuffer(index, count, 9);
			int read = useAsync ? await access.ReadAsync(buffer.AsMemory(index, count), offset) : access.Read(buffer.AsSpan(index, count), offset);
			int expected = (int)Math.Clamp(MessageLength - offset, 0, count);

			using (Assert.Multiple())
			{
				await Assert.That(read).IsEqualTo(expected);
				await XtsTestUtils.AssertBytesEqual(buffer.AsSpan(index, read).ToArray(), plaintext.AsSpan((int)Math.Min(offset, MessageLength), expected).ToArray());
				await Assert.That(buffer.AsMemory(0, index)).All(static value => value is DestinationSentinel);
				await Assert.That(buffer.AsMemory(index + read)).All(static value => value is DestinationSentinel);
			}
		}
	}

	public static IEnumerable<Func<DamageCase>> UnauthenticLengths()
	{
		yield return () => new DamageCase("ends on a chunk boundary", static ciphertext => ciphertext.AsSpan(0, GetChunkOffset(3)).ToArray(), 0);
		yield return () => new DamageCase("last chunk cut short", static ciphertext => ciphertext.AsSpan(0, ciphertext.Length - 1).ToArray(), 0);
		yield return () => new DamageCase("cut inside a full chunk", static ciphertext => ciphertext.AsSpan(0, GetChunkOffset(2) + 8000).ToArray(), 0);
		yield return () => new DamageCase("one byte appended", static ciphertext => [.. ciphertext, 0], 0);
		yield return () => new DamageCase("last chunk modified", static ciphertext => Flip(ciphertext, ciphertext.Length - 1), 0);
		yield return () => new DamageCase("header modified", static ciphertext => Flip(ciphertext, 0), 0);
		yield return () => new DamageCase("shorter than a header", static ciphertext => ciphertext.AsSpan(0, HeaderSize - 1).ToArray(), 0);
		yield return () => new DamageCase("header only", static ciphertext => ciphertext.AsSpan(0, HeaderSize).ToArray(), 0);
	}

	// Creation checks the header and authenticates the last chunk, so a truncated or extended message fails before any read. A failed creation leaves the storage open.
	[Test]
	[MethodDataSource(nameof(UnauthenticLengths))]
	public async Task CreationAuthenticatesTheLength(DamageCase scenario)
	{
		byte[] key = NewKey();
		byte[] damaged = scenario.Damage(Encrypt(key, CreateDeterministicSource(MessageLength)));

		foreach (ChunkedStorageKind kind in Enum.GetValues<ChunkedStorageKind>())
		{
			foreach (bool useAsync in (bool[])[false, true])
			{
				using ChunkedStorage storage = new(kind, damaged, useAsync);
				await Assert.That(() => (Task)storage.OpenAsync<Cobblestone128Cipher>(key, MessageContext, useAsync)).ThrowsExactly<AuthenticationTagMismatchException>();
				await Assert.That(storage.IsOpen).IsTrue();
			}
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task CreationChecksTheKeyAndContext([Matrix] bool useAsync)
	{
		byte[] key = NewKey();
		using ChunkedStorage storage = new(ChunkedStorageKind.Stream, Encrypt(key, CreateDeterministicSource(100)), useAsync);

		using (Assert.Multiple())
		{
			await Assert.That(() => (Task)storage.OpenAsync<Cobblestone128Cipher>(NewKey(), MessageContext, useAsync)).ThrowsExactly<AuthenticationTagMismatchException>();
			await Assert.That(() => (Task)storage.OpenAsync<Cobblestone128Cipher>(key, [], useAsync)).ThrowsExactly<AuthenticationTagMismatchException>();
			await Assert.That(() => (Task)storage.OpenAsync<Cobblestone128Cipher>(key.AsSpan(1).ToArray(), MessageContext, useAsync)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("key");
			await Assert.That(() => (Task)storage.OpenAsync<Cobblestone256Cipher>(key, MessageContext, useAsync)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("key");
		}
	}

	// Each read authenticates the chunks it touches, so damage in one chunk fails only the reads that touch it, and only while they do.
	[Test]
	[MatrixDataSource]
	public async Task OnlyReadsOfDamagedChunksFail([Matrix] bool swapChunks, [Matrix] bool useAsync)
	{
		byte[] key = NewKey();
		byte[] plaintext = CreateDeterministicSource(MessageLength);
		byte[] ciphertext = Encrypt(key, plaintext);
		byte[] damaged = swapChunks ? SwapChunks(ciphertext, 1, 2) : Flip(ciphertext, GetChunkOffset(1) + 5);
		using ChunkedStorage storage = new(ChunkedStorageKind.Stream, damaged, useAsync);
		using ChunkedRandomAccess<Cobblestone128Cipher> access = await storage.OpenAsync<Cobblestone128Cipher>(key, MessageContext, useAsync);
		long damagedEnd = (swapChunks ? 3 : 2) * ChunkSize;

		foreach ((long offset, int count) in ((long, int)[])[(ChunkSize - 1, 2), (ChunkSize, 10), (damagedEnd - 1, 1), (0, MessageLength)])
		{
			await Assert.That(() => ReadAsync(access, new byte[count], offset, useAsync)).ThrowsExactly<AuthenticationTagMismatchException>();
		}

		foreach ((long offset, int count) in ((long, int)[])[(0, ChunkSize), (10, 100), (damagedEnd, MessageLength), (0, ChunkSize)])
		{
			byte[] buffer = new byte[count];
			int read = await ReadAsync(access, buffer, offset, useAsync);
			await XtsTestUtils.AssertBytesEqual(buffer.AsSpan(0, read).ToArray(), plaintext.AsSpan((int)offset, (int)Math.Min(count, MessageLength - offset)).ToArray());
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task ReadsAtOrPastTheEndReturnNothing([Matrix] bool useAsync)
	{
		byte[] key = NewKey();
		using ChunkedStorage storage = new(ChunkedStorageKind.Stream, Encrypt(key, CreateDeterministicSource(MessageLength)), useAsync);
		using ChunkedRandomAccess<Cobblestone128Cipher> access = await storage.OpenAsync<Cobblestone128Cipher>(key, MessageContext, useAsync);
		using CancellationTokenSource cancellation = new();
		await cancellation.CancelAsync();

		using (Assert.Multiple())
		{
			await Assert.That(await ReadAsync(access, new byte[10], MessageLength, useAsync)).IsZero();
			await Assert.That(await ReadAsync(access, new byte[10], long.MaxValue, useAsync)).IsZero();
			await Assert.That(await ReadAsync(access, [], 0, useAsync)).IsZero();
			await Assert.That(() => ReadAsync(access, new byte[10], -1, useAsync)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("offset");
			await Assert.That(() => access.ReadAsync(new byte[10], 0, cancellation.Token).AsTask()).Throws<OperationCanceledException>();
		}
	}

	// The last chunk is cached from creation, so only reads that go to the storage see it shrink.
	[Test]
	[MatrixDataSource]
	public async Task ReadsFailWhenTheStorageShrinks([Matrix] ChunkedStorageKind kind, [Matrix] bool useAsync)
	{
		byte[] key = NewKey();
		byte[] plaintext = CreateDeterministicSource(MessageLength);
		using ChunkedStorage storage = new(kind, Encrypt(key, plaintext), useAsync);
		using ChunkedRandomAccess<Cobblestone128Cipher> access = await storage.OpenAsync<Cobblestone128Cipher>(key, MessageContext, useAsync);
		storage.SetLength(GetChunkOffset(0) + 100);

		byte[] tail = new byte[100];
		await Assert.That(await ReadAsync(access, tail, 3 * ChunkSize, useAsync)).IsEqualTo(100);
		await XtsTestUtils.AssertBytesEqual(tail, plaintext.AsSpan(3 * ChunkSize).ToArray());
		await Assert.That(() => ReadAsync(access, new byte[10], 0, useAsync)).ThrowsExactly<AuthenticationTagMismatchException>();
	}

	[Test]
	[MatrixDataSource]
	public async Task DisposalReleasesTheCipherAndHonorsLeaveOpen([Matrix] ChunkedStorageKind kind, [Matrix] bool leaveOpen)
	{
		byte[] key = NewKey();
		byte[] ciphertext = Encrypt(key, CreateDeterministicSource(2 * ChunkSize + 100));

		using (ChunkedStorage damaged = new(kind, Flip(ciphertext, ciphertext.Length - 1), false))
		{
			await Assert.That(() => (Task)damaged.OpenAsync<LimitedChunkCipher>(key, MessageContext, false, leaveOpen)).ThrowsExactly<AuthenticationTagMismatchException>();
			await Assert.That(LimitedChunkCipher.GetLiveInstances(key)).IsZero();
			await Assert.That(damaged.IsOpen).IsTrue();
		}

		using ChunkedStorage storage = new(kind, ciphertext, false);
		ChunkedRandomAccess<LimitedChunkCipher> access = await storage.OpenAsync<LimitedChunkCipher>(key, MessageContext, false, leaveOpen);
		await Assert.That(LimitedChunkCipher.GetLiveInstances(key)).IsEqualTo(1);
		access.Dispose();
		access.Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(LimitedChunkCipher.GetLiveInstances(key)).IsZero();
			await Assert.That(storage.IsOpen).IsEqualTo(leaveOpen);
			await Assert.That(() => access.Read(new byte[1], 0)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => access.ReadAsync(new byte[1], 0).AsTask()).ThrowsExactly<ObjectDisposedException>();
		}
	}

	[Test]
	public async Task FactoriesValidateTheStorage()
	{
		byte[] key = NewKey();
		using GZipStream unseekable = new(new MemoryStream(), CompressionMode.Decompress);

		using (Assert.Multiple())
		{
			await Assert.That(() => ChunkedRandomAccess.Create<Cobblestone128Cipher>((SafeFileHandle)null!, key)).ThrowsExactly<ArgumentNullException>().WithParameterName("handle");
			await Assert.That(() => (Task)ChunkedRandomAccess.CreateAsync<Cobblestone128Cipher>((SafeFileHandle)null!, key)).ThrowsExactly<ArgumentNullException>().WithParameterName("handle");
			await Assert.That(() => ChunkedRandomAccess.Create<Cobblestone128Cipher>((Stream)null!, key)).ThrowsExactly<ArgumentNullException>().WithParameterName("inner");
			await Assert.That(() => (Task)ChunkedRandomAccess.CreateAsync<Cobblestone128Cipher>((Stream)null!, key)).ThrowsExactly<ArgumentNullException>().WithParameterName("inner");
			await Assert.That(() => ChunkedRandomAccess.Create<Cobblestone128Cipher>(unseekable, key)).ThrowsExactly<ArgumentException>().WithParameterName("inner");
			await Assert.That(() => ChunkedRandomAccess.Create<Cobblestone128Cipher>(new WriteOnlyMemoryStream(), key)).ThrowsExactly<ArgumentException>().WithParameterName("inner");
		}
	}

	/// <summary>Holds a ciphertext in a memory stream or a temporary file and opens positional reads of it.</summary>
	private sealed class ChunkedStorage : IDisposable
	{
		private readonly MemoryStream? _stream;
		private readonly TempFile? _file;
		private readonly SafeFileHandle? _handle;

		public ChunkedStorage(ChunkedStorageKind kind, byte[] ciphertext, bool useAsync)
		{
			if (kind is ChunkedStorageKind.Stream)
			{
				_stream = new MemoryStream();
				_stream.Write(ciphertext);
				return;
			}

			_file = new TempFile();
			File.WriteAllBytes(_file.Path, ciphertext);
			_handle = _file.OpenHandle(useAsync);
		}

		public bool IsOpen => _stream?.CanRead ?? _handle?.IsClosed is false;

		public Task<ChunkedRandomAccess<TCipher>> OpenAsync<TCipher>(byte[] key, byte[] context, bool useAsync, bool leaveOpen = true) where TCipher : class, IChunkedCipher<TCipher>
		{
			return (_stream, _handle) switch
			{
				({ } stream, _) => CreateRandomAccessAsync<TCipher>(stream, key, context, useAsync, leaveOpen),
				(_, { } handle) => useAsync ? ChunkedRandomAccess.CreateAsync<TCipher>(handle, key, context, leaveOpen) : Task.FromResult(ChunkedRandomAccess.Create<TCipher>(handle, key, context, leaveOpen)),
				_ => throw new InvalidOperationException()
			};
		}

		public void SetLength(long length)
		{
			if (_stream is not null)
			{
				_stream.SetLength(length);
			}
			else if (_handle is not null)
			{
				RandomAccess.SetLength(_handle, length);
			}
		}

		public void Dispose()
		{
			_stream?.Dispose();
			_handle?.Dispose();
			_file?.Dispose();
		}
	}
}
