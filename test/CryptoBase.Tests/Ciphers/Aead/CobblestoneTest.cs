using CryptoBase.Ciphers.Aead;
using System.Buffers.Binary;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Aead;

// The Wycheproof tests check known answers; these check the one-shot API and what the vectors leave out.
[GenerateGenericTest(typeof(Cobblestone128Cipher))]
[GenerateGenericTest(typeof(Cobblestone256Cipher))]
internal class CobblestoneTest<TCipher> where TCipher : class, ICobblestoneCipher<TCipher>
{
	private const int HeaderSize = 56;
	private const int ChunkSize = 16384;
	private const int TagSize = 16;
	private const long MaxChunkCount = 1L << 38;

	[Test]
	[MatrixDataSource]
	public async Task OneShotRoundTripsAndMatchesTheChunks([Matrix(0, 1, ChunkSize - 1, ChunkSize, ChunkSize + 1, 3 * ChunkSize, 3 * ChunkSize + 5)] int length)
	{
		byte[] key = CreateDeterministicSource(TCipher.KeySize);
		byte[] context = "file name"u8.ToArray();
		byte[] plaintext = CreateDeterministicSource(length);
		byte[] ciphertext = new byte[TCipher.GetCiphertextLength(length)];
		TCipher.Encrypt(key, plaintext, ciphertext, context);

		byte[] decrypted = new byte[length];
		byte[] fromChunks = new byte[length];
		DecryptChunks(key, ciphertext, fromChunks, context);

		using (Assert.Multiple())
		{
			await Assert.That(ciphertext.Length).IsEqualTo(HeaderSize + length + (length / ChunkSize + 1) * TagSize);
			await Assert.That(TCipher.TryGetPlaintextLength(ciphertext.Length, out long plaintextLength)).IsTrue();
			await Assert.That(plaintextLength).IsEqualTo(length);
			await Assert.That(TCipher.TryDecrypt(key, ciphertext, decrypted, context)).IsTrue();
			await Assert.That(decrypted).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
			await Assert.That(fromChunks).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
			await Assert.That(TCipher.TryDecrypt(key, ciphertext, decrypted, "file name 2"u8)).IsFalse();
		}
	}

	// The vectors only reach chunk 257; this checks the key derivation, the commitment and the nonces of chunk indices up to the largest as the specification defines them.
	[Test]
	public async Task DerivationAndNoncesMatchTheSpecification()
	{
		int keySize = TCipher.KeySize;
		byte[] key = CreateDeterministicSource(keySize);
		byte[] salt = CreateDeterministicSource(24);
		byte[] context = "context\0with a zero byte"u8.ToArray();
		byte[] info = [.. "c2sp.org/chunked-encryption@v1+"u8, .. keySize is 16 ? "AEAD_AES_128_GCM"u8 : "AEAD_AES_256_GCM"u8, 0, .. salt, .. context];
		byte[] firstInput = [.. info, 1];
		byte[] first = HMACSHA512.HashData(key, firstInput);
		byte[] secondInput = [.. first, .. info, 2];
		byte[] okm = [.. first, .. HMACSHA512.HashData(key, secondInput)];
		byte[] aeadKey = okm.AsSpan(0, keySize).ToArray();
		byte[] baseNonce = okm.AsSpan(keySize, 12).ToArray();
		byte[] commitment = okm.AsSpan(keySize + 12, 32).ToArray();

		byte[] header = new byte[HeaderSize];
		using AesGcm oracle = new(aeadKey, TagSize);
		byte[] plaintext = CreateDeterministicSource(33);

		using TCipher cipher = Cobblestone<TCipher>.CreateEncryptor(key, salt, context, header);
		await Assert.That(header).IsEquivalentTo([.. salt, .. commitment], CollectionOrdering.Matching);

		foreach (long index in (long[])[0, 1, 255, 256, 0xFFFF_FFFF, 1L << 32, MaxChunkCount - 1])
		{
			byte[] nonce = (byte[])baseNonce.Clone();
			BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(4), BinaryPrimitives.ReadUInt64BigEndian(nonce.AsSpan(4)) ^ (ulong)index);
			byte[] expected = new byte[plaintext.Length + TagSize];
			oracle.Encrypt(nonce, plaintext, expected.AsSpan(0, plaintext.Length), expected.AsSpan(plaintext.Length));
			byte[] actual = new byte[expected.Length];
			cipher.EncryptChunk(index, plaintext, actual);

			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task LengthsFollowTheChunking()
	{
		long maxMessageLength = MaxChunkCount * ChunkSize - 1;
		long maxCiphertextLength = HeaderSize + (MaxChunkCount - 1) * (ChunkSize + TagSize) + ChunkSize - 1 + TagSize;

		using (Assert.Multiple())
		{
			await Assert.That(TCipher.GetCiphertextLength(0)).IsEqualTo(HeaderSize + TagSize);
			await Assert.That(TCipher.GetCiphertextLength(maxMessageLength)).IsEqualTo(maxCiphertextLength);
			await Assert.That(() => TCipher.GetCiphertextLength(-1)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("plaintextLength");
			await Assert.That(() => TCipher.GetCiphertextLength(maxMessageLength + 1)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("plaintextLength");

			// Too short for a header and a tag, ending on a chunk boundary or inside a tag, or too long.
			foreach (long invalid in (long[])[-1, 0, HeaderSize, HeaderSize + TagSize - 1, HeaderSize + ChunkSize + TagSize, HeaderSize + ChunkSize + 2 * TagSize - 1, maxCiphertextLength + 1, long.MaxValue])
			{
				await Assert.That(TCipher.TryGetPlaintextLength(invalid, out long length)).IsFalse();
				await Assert.That(length).IsZero();
			}

			foreach ((long ciphertextLength, long plaintextLength) in ((long, long)[])[(HeaderSize + TagSize, 0), (HeaderSize + ChunkSize + 2 * TagSize, ChunkSize), (HeaderSize + ChunkSize + 2 * TagSize + 1, ChunkSize + 1), (maxCiphertextLength, maxMessageLength)])
			{
				await Assert.That(TCipher.TryGetPlaintextLength(ciphertextLength, out long length)).IsTrue();
				await Assert.That(length).IsEqualTo(plaintextLength);
			}
		}
	}

	[Test]
	public async Task OneShotValidatesArgumentsBeforeWriting()
	{
		byte[] key = CreateDeterministicSource(TCipher.KeySize);
		byte[] plaintext = CreateDeterministicSource(100);
		byte[] ciphertext = new byte[TCipher.GetCiphertextLength(plaintext.Length)];
		TCipher.Encrypt(key, plaintext, ciphertext);
		byte[] output = new byte[ciphertext.Length + plaintext.Length];
		PrepareDestination(output);

		using (Assert.Multiple())
		{
			await Assert.That(() => TCipher.Encrypt(key.AsSpan(1), plaintext, output)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("key");
			await Assert.That(() => TCipher.Encrypt(key, plaintext, output.AsSpan(0, ciphertext.Length - 1))).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("ciphertext");
			await Assert.That(() => TCipher.TryDecrypt(key.AsSpan(1), ciphertext, output)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("key");
			await Assert.That(() => TCipher.TryDecrypt(key, ciphertext, output.AsSpan(0, plaintext.Length - 1))).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("plaintext");

			// An invalid length fails before the output is checked or touched.
			await Assert.That(TCipher.TryDecrypt(key, ciphertext.AsSpan(0, HeaderSize + TagSize - 1), [])).IsFalse();
			await Assert.That(output).All(static value => value is DestinationSentinel);
		}

		// The one-shot methods cannot work in place, so overlapping buffers throw.
		byte[] shared = new byte[output.Length];
		plaintext.CopyTo(shared, 0);
		await Assert.That(() => TCipher.Encrypt(key, shared.AsSpan(0, plaintext.Length), shared)).ThrowsExactly<ArgumentException>().WithParameterName("ciphertext");
		ciphertext.CopyTo(shared, 0);
		await Assert.That(() => TCipher.TryDecrypt(key, shared.AsSpan(0, ciphertext.Length), shared)).ThrowsExactly<ArgumentException>().WithParameterName("plaintext");
	}

	/// <summary>
	/// Decrypts a whole message chunk by chunk through the instance API.
	/// </summary>
	private static void DecryptChunks(byte[] key, byte[] ciphertext, byte[] plaintext, byte[] context)
	{
		using TCipher cipher = TCipher.CreateDecryptor(key, context, ciphertext.AsSpan(0, HeaderSize));

		for (int index = 0, offset = HeaderSize; offset < ciphertext.Length; ++index, offset += ChunkSize + TagSize)
		{
			ReadOnlySpan<byte> chunk = ciphertext.AsSpan(offset, Math.Min(ChunkSize + TagSize, ciphertext.Length - offset));

			if (!cipher.TryDecryptChunk(index, chunk, plaintext.AsSpan(index * ChunkSize)))
			{
				throw new CryptographicException($"Chunk {index} failed authentication.");
			}
		}
	}
}
