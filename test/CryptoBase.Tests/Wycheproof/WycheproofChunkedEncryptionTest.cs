using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Aead;
using CryptoBase.IO;
using CryptoBase.Tests.IO;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace CryptoBase.Tests.Wycheproof;

// Applies the vectors as doc/c2sp_chunked_encryption.md describes, to the one-shot API, streaming encryption and decryption, and random access.
[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class WycheproofChunkedEncryptionTest
{
	private const string Cobblestone128File = "c2sp_chunked_encryption_aes_128_gcm_test.json";
	private const string Cobblestone256File = "c2sp_chunked_encryption_aes_256_gcm_test.json";

	// Covers both full chunks, which the streams decrypt straight into the caller's buffer, and smaller reads and writes that go through their buffer.
	private static readonly int[] TransferSizes = [1, 7, 509, 4099, 16384, 20000];

	public static IEnumerable<ChunkedEncryptionTestVector> Vectors(string fileName)
	{
		return WycheproofVectors.Load<ChunkedEncryptionTestVector>(fileName);
	}

	public static IEnumerable<ChunkedEncryptionTestVector> ValidVectors(string fileName)
	{
		return Vectors(fileName).Where(static vector => vector.Result is WycheproofResult.Valid);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = [Cobblestone128File])]
	public Task Cobblestone128Decrypt(ChunkedEncryptionTestVector vector)
	{
		return VerifyDecrypt<Cobblestone128Cipher>(vector);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = [Cobblestone256File])]
	public Task Cobblestone256Decrypt(ChunkedEncryptionTestVector vector)
	{
		return VerifyDecrypt<Cobblestone256Cipher>(vector);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = [Cobblestone128File])]
	public Task Cobblestone128StreamingDecryption(ChunkedEncryptionTestVector vector)
	{
		return VerifyStreamingDecryption<Cobblestone128Cipher>(vector);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = [Cobblestone256File])]
	public Task Cobblestone256StreamingDecryption(ChunkedEncryptionTestVector vector)
	{
		return VerifyStreamingDecryption<Cobblestone256Cipher>(vector);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = [Cobblestone128File])]
	public Task Cobblestone128RandomAccess(ChunkedEncryptionTestVector vector)
	{
		return VerifyRandomAccess<Cobblestone128Cipher>(vector);
	}

	[Test]
	[MethodDataSource(nameof(Vectors), Arguments = [Cobblestone256File])]
	public Task Cobblestone256RandomAccess(ChunkedEncryptionTestVector vector)
	{
		return VerifyRandomAccess<Cobblestone256Cipher>(vector);
	}

	[Test]
	[MethodDataSource(nameof(ValidVectors), Arguments = [Cobblestone128File])]
	public Task Cobblestone128StreamingEncryption(ChunkedEncryptionTestVector vector)
	{
		return VerifyStreamingEncryption<Cobblestone128Cipher>(vector);
	}

	[Test]
	[MethodDataSource(nameof(ValidVectors), Arguments = [Cobblestone256File])]
	public Task Cobblestone256StreamingEncryption(ChunkedEncryptionTestVector vector)
	{
		return VerifyStreamingEncryption<Cobblestone256Cipher>(vector);
	}

	// Decrypts with the one-shot API, then re-encrypts the message with the salt of the vector, which must reproduce the ciphertext.
	private static async Task VerifyDecrypt<TCipher>(ChunkedEncryptionTestVector vector) where TCipher : class, ICobblestoneCipher<TCipher>
	{
		byte[] ciphertext = vector.DecompressCiphertext();
		byte[] plaintext = new byte[ciphertext.Length];
		TestUtils.PrepareDestination(plaintext);

		if (vector.Flags.Contains("InvalidKeySize"))
		{
			await Assert.That(() => Cobblestone<TCipher>.TryDecrypt(vector.Key, ciphertext, plaintext, vector.Ctx)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("key");
			return;
		}

		bool decrypted = Cobblestone<TCipher>.TryDecrypt(vector.Key, ciphertext, plaintext, vector.Ctx);

		if (vector.Result is WycheproofResult.Invalid)
		{
			// A failure clears the output that a message of this length would fill, and only that.
			int cleared = Cobblestone.TryGetPlaintextLength(ciphertext.Length, out long length) ? (int)length : 0;

			using (Assert.Multiple())
			{
				await Assert.That(decrypted).IsFalse();
				await Assert.That(plaintext.AsMemory(0, cleared)).All(static value => value is 0);
				await Assert.That(plaintext.AsMemory(cleared)).All(static value => value is TestUtils.DestinationSentinel);
			}

			return;
		}

		await Assert.That(decrypted).IsTrue();
		byte[] message = await GetMessage(vector, plaintext);
		byte[] reencrypted = new byte[ciphertext.Length];
		Cobblestone<TCipher>.Encrypt(vector.Key, ciphertext.AsSpan(0, Cobblestone.SaltSize), message, reencrypted, vector.Ctx);
		await XtsTestUtils.AssertBytesEqual(reencrypted, ciphertext);
	}

	// A streaming decrypter may return the valid prefix that PartialPlaintext describes before it fails; this one returns every chunk it authenticates, so it returns exactly that prefix, and nothing for other invalid vectors. It must then keep failing.
	private static async Task VerifyStreamingDecryption<TCipher>(ChunkedEncryptionTestVector vector) where TCipher : class, IChunkedCipher<TCipher>
	{
		byte[] ciphertext = vector.DecompressCiphertext();

		foreach (bool useAsync in (bool[])[false, true])
		{
			// Inner reads return less than a chunk, so the stream must gather each chunk.
			using LimitedReadMemoryStream inner = new(ciphertext, 5000);

			if (vector.Flags.Contains("InvalidKeySize"))
			{
				await Assert.That(() => (Task)ChunkedTestUtils.CreateDecryptionStreamAsync<TCipher>(inner, vector.Key, vector.Ctx, useAsync)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("key");
				continue;
			}

			if (vector.Flags.Contains("HeaderFailure"))
			{
				await Assert.That(() => (Task)ChunkedTestUtils.CreateDecryptionStreamAsync<TCipher>(inner, vector.Key, vector.Ctx, useAsync)).ThrowsExactly<AuthenticationTagMismatchException>();
				continue;
			}

			await using ChunkedDecryptionStream<TCipher> stream = await ChunkedTestUtils.CreateDecryptionStreamAsync<TCipher>(inner, vector.Key, vector.Ctx, useAsync);
			(byte[] output, Exception? failure) = await ChunkedTestUtils.ReadUntilEndOrFailure(stream, TransferSizes, useAsync);
			await Assert.That(output.Length).IsEqualTo(vector.MsgLength ?? 0);

			if (vector.MsgLength is not null)
			{
				await GetMessage(vector, output);
			}

			if (vector.Result is WycheproofResult.Valid)
			{
				await Assert.That(failure).IsNull();
				continue;
			}

			await Assert.That(failure).IsTypeOf<AuthenticationTagMismatchException>();
			await ChunkedTestUtils.AssertKeepsFailing(stream);
		}
	}

	// Creating an instance authenticates the length, which succeeds for the valid vectors and those with ValidFinalChunk only. Reading the whole message must still fail for the latter, while reading the valid prefix that PartialPlaintext describes may succeed.
	private static async Task VerifyRandomAccess<TCipher>(ChunkedEncryptionTestVector vector) where TCipher : class, IChunkedCipher<TCipher>
	{
		byte[] ciphertext = vector.DecompressCiphertext();

		foreach (bool useAsync in (bool[])[false, true])
		{
			using MemoryStream inner = new(ciphertext, false);

			if (vector.Flags.Contains("InvalidKeySize"))
			{
				await Assert.That(() => (Task)ChunkedTestUtils.CreateRandomAccessAsync<TCipher>(inner, vector.Key, vector.Ctx, useAsync)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("key");
				continue;
			}

			if (vector.Result is WycheproofResult.Invalid && !vector.Flags.Contains("ValidFinalChunk"))
			{
				await Assert.That(() => (Task)ChunkedTestUtils.CreateRandomAccessAsync<TCipher>(inner, vector.Key, vector.Ctx, useAsync)).ThrowsExactly<AuthenticationTagMismatchException>();
				continue;
			}

			using ChunkedRandomAccess<TCipher> access = await ChunkedTestUtils.CreateRandomAccessAsync<TCipher>(inner, vector.Key, vector.Ctx, useAsync);
			byte[] whole = new byte[access.Length];

			if (vector.Result is WycheproofResult.Invalid)
			{
				await Assert.That(() => ChunkedTestUtils.ReadAsync(access, whole, 0, useAsync)).ThrowsExactly<AuthenticationTagMismatchException>();

				if (vector.MsgLength is { } prefixLength)
				{
					byte[] prefix = new byte[prefixLength];
					await Assert.That(await ChunkedTestUtils.ReadAsync(access, prefix, 0, useAsync)).IsEqualTo(prefixLength);
					await GetMessage(vector, prefix);
				}

				continue;
			}

			await Assert.That(access.Length).IsEqualTo(vector.MsgLength ?? -1);
			await Assert.That(await ChunkedTestUtils.ReadAsync(access, whole, 0, useAsync)).IsEqualTo(whole.Length);
			await GetMessage(vector, whole);

			// Ranges that start and end inside chunks, cross chunk boundaries, or reach the end.
			foreach ((long offset, int count) in ((long, int)[])[(1, 5), (16380, 9), (16383, 16386), (Math.Max(whole.Length - 3, 0), 10), (whole.Length, 1)])
			{
				byte[] range = new byte[count];
				int expected = (int)Math.Clamp(whole.Length - offset, 0, count);
				await Assert.That(await ChunkedTestUtils.ReadAsync(access, range, offset, useAsync)).IsEqualTo(expected);
				await XtsTestUtils.AssertBytesEqual(range.AsSpan(0, expected).ToArray(), whole.AsSpan((int)Math.Min(offset, whole.Length), expected).ToArray());
			}
		}
	}

	// Whatever the sizes of the writes, the stream output must decrypt to the message of the vector under its key and context.
	private static async Task VerifyStreamingEncryption<TCipher>(ChunkedEncryptionTestVector vector) where TCipher : class, ICobblestoneCipher<TCipher>
	{
		byte[] ciphertext = vector.DecompressCiphertext();
		byte[] plaintext = new byte[ciphertext.Length];
		await Assert.That(Cobblestone<TCipher>.TryDecrypt(vector.Key, ciphertext, plaintext, vector.Ctx)).IsTrue();
		byte[] message = await GetMessage(vector, plaintext);

		foreach (bool useAsync in (bool[])[false, true])
		{
			using MemoryStream output = new();

			await using (ChunkedEncryptionStream<TCipher> stream = ChunkedEncryptionStream.Create<TCipher>(output, vector.Key, vector.Ctx, leaveOpen: true))
			{
				await StreamTestUtils.WriteInChunksAsync(stream, message, useAsync, TransferSizes);
				await ChunkedTestUtils.FlushFinalChunkAsync(stream, useAsync);
			}

			byte[] decrypted = new byte[message.Length];
			await Assert.That(output.Length).IsEqualTo(ciphertext.Length);
			await Assert.That(Cobblestone<TCipher>.TryDecrypt(vector.Key, output.ToArray(), decrypted, vector.Ctx)).IsTrue();
			await XtsTestUtils.AssertBytesEqual(decrypted, message);
		}
	}

	/// <summary>
	/// Checks that <paramref name="plaintext" /> starts with the message, or the valid prefix, that the vector describes, and returns it.
	/// </summary>
	private static async Task<byte[]> GetMessage(ChunkedEncryptionTestVector vector, byte[] plaintext)
	{
		int length = vector.MsgLength ?? throw new InvalidOperationException("The vector describes no message.");
		byte[] hash = vector.MsgSha512 ?? throw new InvalidOperationException("The vector has no message hash.");
		await Assert.That(plaintext.Length).IsGreaterThanOrEqualTo(length);

		byte[] message = plaintext.AsSpan(0, length).ToArray();
		await Assert.That(SHA512.HashData(message)).IsEquivalentTo(hash, CollectionOrdering.Matching);
		return message;
	}
}
