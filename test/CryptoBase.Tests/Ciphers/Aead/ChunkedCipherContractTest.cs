using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Aead;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Aead;

// Checks every IChunkedCipher against the behavior its documentation promises; the Wycheproof tests check the values.
[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
[GenerateGenericTest(typeof(Cobblestone128Cipher))]
[GenerateGenericTest(typeof(Cobblestone256Cipher))]
public class ChunkedCipherContractTest<T> where T : class, IChunkedCipher<T>
{
	private static byte[] Key => CreateDeterministicSource(T.KeySize);

	private static byte[] Context => "context"u8.ToArray();

	[Test]
	public async Task ChunksDecryptOnlyAtTheirIndex()
	{
		byte[] header = new byte[T.HeaderSize];
		using T encryptor = T.CreateEncryptor(Key, Context, header);
		using T decryptor = T.CreateDecryptor(Key, Context, header);

		foreach (int length in (int[])[0, 1, 16, 4097, T.ChunkSize - 1, T.ChunkSize])
		{
			foreach (long index in (long[])[0, 1, T.MaxChunkCount - 1])
			{
				byte[] plaintext = CreateDeterministicSource(length);
				byte[] ciphertext = new byte[length + T.TagSize];
				byte[] decrypted = new byte[length];
				encryptor.EncryptChunk(index, plaintext, ciphertext);

				using (Assert.Multiple())
				{
					await Assert.That(decryptor.TryDecryptChunk(index, ciphertext, decrypted)).IsTrue();
					await Assert.That(decrypted).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
					await Assert.That(decryptor.TryDecryptChunk(index ^ 1, ciphertext, decrypted)).IsFalse();
				}
			}
		}
	}

	[Test]
	public async Task EachMessageGetsANewHeaderAndKeys()
	{
		byte[] firstHeader = new byte[T.HeaderSize];
		byte[] secondHeader = new byte[T.HeaderSize];
		byte[] plaintext = CreateDeterministicSource(100);
		byte[] firstCiphertext = new byte[plaintext.Length + T.TagSize];
		byte[] secondCiphertext = new byte[plaintext.Length + T.TagSize];

		using (T first = T.CreateEncryptor(Key, Context, firstHeader))
		using (T second = T.CreateEncryptor(Key, Context, secondHeader))
		{
			first.EncryptChunk(0, plaintext, firstCiphertext);
			second.EncryptChunk(0, plaintext, secondCiphertext);
		}

		using T secondDecryptor = T.CreateDecryptor(Key, Context, secondHeader);

		using (Assert.Multiple())
		{
			await Assert.That(firstHeader).IsNotEquivalentTo(secondHeader);
			await Assert.That(firstCiphertext).IsNotEquivalentTo(secondCiphertext);
			await Assert.That(secondDecryptor.TryDecryptChunk(0, firstCiphertext, new byte[plaintext.Length])).IsFalse();
		}
	}

	[Test]
	public async Task DecryptorRejectsAnotherKeyContextOrHeader()
	{
		byte[] header = new byte[T.HeaderSize];
		T.CreateEncryptor(Key, Context, header).Dispose();
		byte[] otherKey = Flip(Key, 0);

		using (Assert.Multiple())
		{
			await Assert.That(() => T.CreateDecryptor(otherKey, Context, header)).ThrowsExactly<AuthenticationTagMismatchException>();
			await Assert.That(() => T.CreateDecryptor(Key, [], header)).ThrowsExactly<AuthenticationTagMismatchException>();
			await Assert.That(() => T.CreateDecryptor(Key, [.. Context, 0], header)).ThrowsExactly<AuthenticationTagMismatchException>();

			for (int i = 0; i < header.Length; ++i)
			{
				byte[] modified = Flip(header, i);
				await Assert.That(() => T.CreateDecryptor(Key, Context, modified)).ThrowsExactly<AuthenticationTagMismatchException>();
			}
		}
	}

	[Test]
	public async Task FactoriesValidateLengths()
	{
		byte[] header = new byte[T.HeaderSize + 1];
		T.CreateEncryptor(Key, Context, header).Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(() => T.CreateEncryptor(Key.AsSpan(1), Context, header)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("key");
			await Assert.That(() => T.CreateEncryptor([.. Key, 0], Context, header)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("key");
			await Assert.That(() => T.CreateEncryptor(Key, Context, header.AsSpan(2))).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("header");
			await Assert.That(() => T.CreateDecryptor(Key.AsSpan(1), Context, header.AsSpan(0, T.HeaderSize))).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("key");
			await Assert.That(() => T.CreateDecryptor(Key, Context, header.AsSpan(2))).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("header");
			await Assert.That(() => T.CreateDecryptor(Key, Context, header)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("header");
		}

		// A longer header buffer receives the header at its start.
		T.CreateDecryptor(Key, Context, header.AsSpan(0, T.HeaderSize)).Dispose();
	}

	[Test]
	public async Task ChunkMethodsValidateArgumentsBeforeWriting()
	{
		byte[] header = new byte[T.HeaderSize];
		using T cipher = T.CreateEncryptor(Key, Context, header);
		byte[] full = CreateDeterministicSource(T.ChunkSize + 1);
		byte[] output = new byte[T.ChunkSize + T.TagSize + 1];
		PrepareDestination(output);

		using (Assert.Multiple())
		{
			await Assert.That(() => cipher.EncryptChunk(-1, full.AsSpan(0, 1), output)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("index");
			await Assert.That(() => cipher.EncryptChunk(T.MaxChunkCount, full.AsSpan(0, 1), output)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("index");
			await Assert.That(() => cipher.EncryptChunk(0, full, output)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("plaintext");
			await Assert.That(() => cipher.EncryptChunk(0, full.AsSpan(0, 10), output.AsSpan(0, 10 + T.TagSize - 1))).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("ciphertext");
			await Assert.That(() => cipher.TryDecryptChunk(-1, full.AsSpan(0, T.TagSize), output)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("index");
			await Assert.That(() => cipher.TryDecryptChunk(T.MaxChunkCount, full.AsSpan(0, T.TagSize), output)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("index");
			await Assert.That(() => cipher.TryDecryptChunk(0, full.AsSpan(0, T.TagSize - 1), output)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("ciphertext");
			await Assert.That(() => cipher.TryDecryptChunk(0, output, full)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("ciphertext");
			await Assert.That(() => cipher.TryDecryptChunk(0, full.AsSpan(0, T.TagSize + 10), output.AsSpan(0, 9))).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("plaintext");
			await Assert.That(output).All(static value => value is DestinationSentinel);
		}
	}

	[Test]
	public async Task BuffersMayCoincideButNotOverlapAtDifferentStarts()
	{
		byte[] header = new byte[T.HeaderSize];
		using T encryptor = T.CreateEncryptor(Key, Context, header);
		using T decryptor = T.CreateDecryptor(Key, Context, header);
		byte[] plaintext = CreateDeterministicSource(1000);
		byte[] expected = new byte[plaintext.Length + T.TagSize];
		encryptor.EncryptChunk(5, plaintext, expected);

		byte[] buffer = new byte[expected.Length + 1];
		plaintext.CopyTo(buffer, 0);
		encryptor.EncryptChunk(5, buffer.AsSpan(0, plaintext.Length), buffer);
		await Assert.That(buffer.AsSpan(0, expected.Length).ToArray()).IsEquivalentTo(expected, CollectionOrdering.Matching);
		await Assert.That(decryptor.TryDecryptChunk(5, buffer.AsSpan(0, expected.Length), buffer)).IsTrue();
		await Assert.That(buffer.AsSpan(0, plaintext.Length).ToArray()).IsEquivalentTo(plaintext, CollectionOrdering.Matching);

		using (Assert.Multiple())
		{
			await Assert.That(() => encryptor.EncryptChunk(5, buffer.AsSpan(1, plaintext.Length), buffer)).ThrowsExactly<ArgumentException>().WithParameterName("ciphertext");
			await Assert.That(() => decryptor.TryDecryptChunk(5, buffer.AsSpan(0, expected.Length), buffer.AsSpan(1))).ThrowsExactly<ArgumentException>().WithParameterName("plaintext");
		}
	}

	[Test]
	public async Task FailedDecryptionClearsOnlyThePlaintextPrefix()
	{
		byte[] header = new byte[T.HeaderSize];
		using T encryptor = T.CreateEncryptor(Key, Context, header);
		using T decryptor = T.CreateDecryptor(Key, Context, header);
		byte[] ciphertext = new byte[300 + T.TagSize];
		encryptor.EncryptChunk(0, CreateDeterministicSource(300), ciphertext);
		byte[] plaintext = new byte[400];

		for (int i = 0; i < ciphertext.Length; i += 37)
		{
			PrepareDestination(plaintext);

			using (Assert.Multiple())
			{
				await Assert.That(decryptor.TryDecryptChunk(0, Flip(ciphertext, i), plaintext)).IsFalse();
				await Assert.That(plaintext.AsMemory(0, 300)).All(static value => value is 0);
				await Assert.That(plaintext.AsMemory(300)).All(static value => value is DestinationSentinel);
			}
		}
	}

	[Test]
	public async Task DisposalIsIdempotentAndEndsChunkOperations()
	{
		byte[] header = new byte[T.HeaderSize];
		T cipher = T.CreateEncryptor(Key, Context, header);
		cipher.Dispose();
		cipher.Dispose();
		byte[] buffer = new byte[T.TagSize + 1];

		using (Assert.Multiple())
		{
			await Assert.That(() => cipher.EncryptChunk(0, buffer.AsSpan(0, 1), buffer)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => cipher.TryDecryptChunk(0, buffer, buffer)).ThrowsExactly<ObjectDisposedException>();
		}
	}
}
