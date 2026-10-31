using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Aead;
using CryptoBase.IO;
using CryptoBase.IO.Chunked;
using System.Diagnostics;
using static CryptoBase.Tests.IO.ChunkedTestUtils;

namespace CryptoBase.Tests.IO;

// Random access takes the message length from ChunkLayout and the encryption stream its limit, while the one-shot API takes both from the cipher. The two assemblies each follow the layout that IChunkedCipher documents, so they must agree, above all on the lengths that end on a chunk boundary.
public class ChunkLayoutTest
{
	[Test]
	public async Task LengthRulesMatchTheCipher()
	{
		long maxMessageLength = ChunkLayout<Cobblestone128Cipher>.Sizes.MaxMessageLength;

		using (Assert.Multiple())
		{
			foreach (long chunks in (long[])[0, 1, 2, Cobblestone128Cipher.MaxChunkCount - 1, Cobblestone128Cipher.MaxChunkCount])
			{
				foreach (long extra in (long[])[-1, 0, 1, TagSize - 1, TagSize, TagSize + 1, EncryptedChunkSize - 1])
				{
					await AssertSameLength(HeaderSize + chunks * EncryptedChunkSize + extra);
				}
			}

			foreach (long ciphertextLength in (long[])[long.MinValue, -1, 0, long.MaxValue])
			{
				await AssertSameLength(ciphertextLength);
			}

			await Assert.That(Cobblestone128Cipher.TryGetPlaintextLength(Cobblestone128Cipher.GetCiphertextLength(maxMessageLength), out long length)).IsTrue();
			await Assert.That(length).IsEqualTo(maxMessageLength);
			await Assert.That(() => Cobblestone128Cipher.GetCiphertextLength(maxMessageLength + 1)).ThrowsExactly<ArgumentOutOfRangeException>();
		}
	}

	// Sizes whose sums overflow an int must fail the layout check, not a later allocation.
	[Test]
	public async Task SizesThatOverflowAreNotSupported()
	{
		await Assert.That(() => ChunkedEncryptionStream.Create<OversizedChunkCipher>(new MemoryStream(), new byte[OversizedChunkCipher.KeySize])).ThrowsExactly<NotSupportedException>();
	}

	private static async Task AssertSameLength(long ciphertextLength)
	{
		bool valid = Cobblestone128Cipher.TryGetPlaintextLength(ciphertextLength, out long expected);
		await Assert.That(ChunkLayout<Cobblestone128Cipher>.TryGetPlaintextLength(ciphertextLength, out long actual)).IsEqualTo(valid);
		await Assert.That(actual).IsEqualTo(expected);
	}
}

/// <summary>
/// A cipher whose header and tag are so large that their sum overflows an int.
/// </summary>
internal sealed class OversizedChunkCipher : IChunkedCipher<OversizedChunkCipher>
{
	public static int KeySize => 16;

	public static int HeaderSize => int.MaxValue;

	public static int ChunkSize => 1;

	public static int TagSize => int.MaxValue - 20;

	public static long MaxChunkCount => 1;

	public static OversizedChunkCipher CreateEncryptor(scoped ReadOnlySpan<byte> key, scoped ReadOnlySpan<byte> context, scoped Span<byte> header)
	{
		throw new UnreachableException();
	}

	public static OversizedChunkCipher CreateDecryptor(scoped ReadOnlySpan<byte> key, scoped ReadOnlySpan<byte> context, scoped ReadOnlySpan<byte> header)
	{
		throw new UnreachableException();
	}

	public void EncryptChunk(long index, scoped ReadOnlySpan<byte> plaintext, scoped Span<byte> ciphertext)
	{
		throw new UnreachableException();
	}

	public bool TryDecryptChunk(long index, scoped ReadOnlySpan<byte> ciphertext, scoped Span<byte> plaintext)
	{
		throw new UnreachableException();
	}

	public void Dispose()
	{
	}
}
