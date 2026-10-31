using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Aead;
using CryptoBase.IO;
using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace CryptoBase.Tests.IO;

internal static class ChunkedTestUtils
{
	public const int HeaderSize = 56;
	public const int ChunkSize = 16384;
	public const int TagSize = 16;
	public const int EncryptedChunkSize = ChunkSize + TagSize;

	public static readonly byte[] MessageContext = "chunked test"u8.ToArray();

	// A new key per test keeps the instance counts of LimitedChunkCipher apart.
	public static byte[] NewKey()
	{
		return RandomNumberGenerator.GetBytes(Cobblestone128Cipher.KeySize);
	}

	public static int GetChunkOffset(int index)
	{
		return HeaderSize + index * EncryptedChunkSize;
	}

	/// <summary>Encrypts with the one-shot API, independently of CryptoBase.IO.</summary>
	public static byte[] Encrypt(byte[] key, byte[] plaintext)
	{
		byte[] ciphertext = new byte[Cobblestone128Cipher.GetCiphertextLength(plaintext.Length)];
		Cobblestone128Cipher.Encrypt(key, plaintext, ciphertext, MessageContext);
		return ciphertext;
	}

	/// <summary>Decrypts with the one-shot API, independently of CryptoBase.IO.</summary>
	public static bool TryDecrypt(byte[] key, byte[] ciphertext, out byte[] plaintext)
	{
		plaintext = Cobblestone128Cipher.TryGetPlaintextLength(ciphertext.Length, out long length) ? new byte[length] : [];
		return Cobblestone128Cipher.TryDecrypt(key, ciphertext, plaintext, MessageContext);
	}

	/// <summary>Opens a decryption stream with the synchronous or the asynchronous factory.</summary>
	public static Task<ChunkedDecryptionStream<TCipher>> CreateDecryptionStreamAsync<TCipher>(Stream inner, byte[] key, byte[] context, bool useAsync, bool leaveOpen = true) where TCipher : class, IChunkedCipher<TCipher>
	{
		return useAsync ? ChunkedDecryptionStream.CreateAsync<TCipher>(inner, key, context, leaveOpen) : Task.FromResult(ChunkedDecryptionStream.Create<TCipher>(inner, key, context, leaveOpen));
	}

	/// <summary>Opens random access over a stream with the synchronous or the asynchronous factory.</summary>
	public static Task<ChunkedRandomAccess<TCipher>> CreateRandomAccessAsync<TCipher>(Stream inner, byte[] key, byte[] context, bool useAsync, bool leaveOpen = true) where TCipher : class, IChunkedCipher<TCipher>
	{
		return useAsync ? ChunkedRandomAccess.CreateAsync<TCipher>(inner, key, context, leaveOpen) : Task.FromResult(ChunkedRandomAccess.Create<TCipher>(inner, key, context, leaveOpen));
	}

	public static async Task<int> ReadAsync<TCipher>(ChunkedRandomAccess<TCipher> access, byte[] buffer, long offset, bool useAsync) where TCipher : class, IChunkedCipher<TCipher>
	{
		return useAsync ? await access.ReadAsync(buffer, offset) : access.Read(buffer, offset);
	}

	public static async Task FlushFinalChunkAsync<TCipher>(ChunkedEncryptionStream<TCipher> stream, bool useAsync) where TCipher : class, IChunkedCipher<TCipher>
	{
		if (useAsync)
		{
			await stream.FlushFinalChunkAsync();
		}
		else
		{
			stream.FlushFinalChunk();
		}
	}

	/// <summary>Reads <paramref name="stream" /> in calls that cycle through <paramref name="readSizes" /> until it ends or fails, and returns what it read and the failure.</summary>
	public static async Task<(byte[] Output, Exception? Failure)> ReadUntilEndOrFailure(Stream stream, int[] readSizes, bool useAsync)
	{
		using MemoryStream output = new();
		byte[] buffer = new byte[readSizes.Max()];

		try
		{
			for (int i = 0; ; ++i)
			{
				Memory<byte> chunk = buffer.AsMemory(0, readSizes[i % readSizes.Length]);
				int read = useAsync ? await stream.ReadAsync(chunk) : stream.Read(chunk.Span);

				if (read is 0)
				{
					return (output.ToArray(), null);
				}

				output.Write(buffer, 0, read);
			}
		}
		catch (Exception e)
		{
			return (output.ToArray(), e);
		}
	}

	/// <summary>Checks that every later read fails with the authentication error rather than ending cleanly.</summary>
	public static async Task AssertKeepsFailing(Stream stream)
	{
		byte[] buffer = new byte[100];

		for (int i = 0; i < 3; ++i)
		{
			await Assert.That(() => stream.Read(buffer)).ThrowsExactly<AuthenticationTagMismatchException>();
			await Assert.That(() => stream.ReadAsync(buffer).AsTask()).ThrowsExactly<AuthenticationTagMismatchException>();
			await Assert.That(() => stream.ReadByte()).ThrowsExactly<AuthenticationTagMismatchException>();
			await Assert.That(() => stream.Read([])).ThrowsExactly<AuthenticationTagMismatchException>();
		}
	}

	public static byte[] SwapChunks(byte[] ciphertext, int first, int second)
	{
		byte[] swapped = (byte[])ciphertext.Clone();
		ciphertext.AsSpan(GetChunkOffset(first), EncryptedChunkSize).CopyTo(swapped.AsSpan(GetChunkOffset(second)));
		ciphertext.AsSpan(GetChunkOffset(second), EncryptedChunkSize).CopyTo(swapped.AsSpan(GetChunkOffset(first)));
		return swapped;
	}
}

/// <summary>
/// Cobblestone-128 with a limit of three chunks per message, which counts its live instances per key so that tests can see the limit and disposal.
/// </summary>
internal sealed class LimitedChunkCipher : IChunkedCipher<LimitedChunkCipher>
{
	private static readonly ConcurrentDictionary<string, int> LiveInstances = new();

	private readonly Cobblestone128Cipher _inner;
	private readonly string _keyId;
	private bool _disposed;

	private LimitedChunkCipher(Cobblestone128Cipher inner, ReadOnlySpan<byte> key)
	{
		_inner = inner;
		_keyId = Convert.ToHexString(key);
		LiveInstances.AddOrUpdate(_keyId, 1, static (_, count) => count + 1);
	}

	public static int KeySize => Cobblestone128Cipher.KeySize;

	public static int HeaderSize => Cobblestone128Cipher.HeaderSize;

	public static int ChunkSize => Cobblestone128Cipher.ChunkSize;

	public static int TagSize => Cobblestone128Cipher.TagSize;

	public static long MaxChunkCount => 3;

	public static long MaxMessageLength => MaxChunkCount * ChunkSize - 1;

	public static LimitedChunkCipher CreateEncryptor(scoped ReadOnlySpan<byte> key, scoped ReadOnlySpan<byte> context, scoped Span<byte> header)
	{
		return new LimitedChunkCipher(Cobblestone128Cipher.CreateEncryptor(key, context, header), key);
	}

	public static LimitedChunkCipher CreateDecryptor(scoped ReadOnlySpan<byte> key, scoped ReadOnlySpan<byte> context, scoped ReadOnlySpan<byte> header)
	{
		return new LimitedChunkCipher(Cobblestone128Cipher.CreateDecryptor(key, context, header), key);
	}

	public static int GetLiveInstances(byte[] key)
	{
		return LiveInstances.GetValueOrDefault(Convert.ToHexString(key));
	}

	public void EncryptChunk(long index, scoped ReadOnlySpan<byte> plaintext, scoped Span<byte> ciphertext)
	{
		_inner.EncryptChunk(index, plaintext, ciphertext);
	}

	public bool TryDecryptChunk(long index, scoped ReadOnlySpan<byte> ciphertext, scoped Span<byte> plaintext)
	{
		return _inner.TryDecryptChunk(index, ciphertext, plaintext);
	}

	public void Dispose()
	{
		if (_disposed)
		{
			return;
		}

		_disposed = true;
		_inner.Dispose();
		LiveInstances.AddOrUpdate(_keyId, 0, static (_, count) => count - 1);
	}
}

/// <summary>A memory stream whose writes throw <see cref="IOException" /> after <c>allowedWrites</c> successful ones.</summary>
internal sealed class FailingWriteMemoryStream(int allowedWrites) : MemoryStream
{
	private int _remaining = allowedWrites;

	// MemoryStream sends span writes of derived types to this overload.
	public override void Write(byte[] buffer, int offset, int count)
	{
		if (_remaining-- <= 0)
		{
			throw new IOException("Write failed.");
		}

		base.Write(buffer, offset, count);
	}

	public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
	{
		await Task.Yield();
		Write(buffer.Span);
	}
}
