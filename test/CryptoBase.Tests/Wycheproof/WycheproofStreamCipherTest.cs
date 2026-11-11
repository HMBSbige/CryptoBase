using CryptoBase.Ciphers.Streams;
using System.Buffers.Binary;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Wycheproof;

public class WycheproofStreamCipherTest
{
	// The keystream from a counter next to the carry into its high word, which only XChaCha20 has, or next to its end: block 0xFFFFFFFF of the IETF variant, whose counter DTLS 1.3 and QUIC header protection take from ciphertext. A message that needs a block past the last counter is rejected whole.
	[Test]
	[WycheproofVectors<StreamCipherTestGroup, StreamCipherTestVector>("chacha20_counter_test.json")]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before the cipher is disposed.")]
	public async Task ChaCha20Counter(StreamCipherTestVector vector)
	{
		using SnuffleCipher cipher = Create(vector);
		byte[] destination = CreateGuardedBuffer(0, vector.Msg.Length);

		using (Assert.Multiple())
		{
			if (vector.Ct is null)
			{
				await Assert.That(vector.Result).IsEqualTo(WycheproofResult.Invalid);
				await Assert.That(() => cipher.Xor(vector.Msg, destination)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("source");
				await Assert.That(destination).All(static value => value is DestinationSentinel);
				return;
			}

			cipher.Xor(vector.Msg, destination);

			await Assert.That(vector.Result).IsEqualTo(WycheproofResult.Valid);
			await Assert.That(destination.AsSpan(0, vector.Msg.Length).ToArray()).IsEquivalentTo(vector.Ct, CollectionOrdering.Matching);
			await Assert.That(destination.AsSpan(vector.Msg.Length).ToArray()).All(static value => value is DestinationSentinel);
		}
	}

	private static SnuffleCipher Create(StreamCipherTestVector vector)
	{
		switch (vector.Algorithm)
		{
			case "ChaCha20-IETF":
			{
				ChaCha20Cipher cipher = new(vector.Key, vector.Iv);
				cipher.SetCounter(BinaryPrimitives.ReadUInt32LittleEndian(vector.InitialCounter));
				return cipher;
			}
			case "XChaCha20":
			{
				XChaCha20Cipher cipher = new(vector.Key, vector.Iv);
				cipher.SetCounter(BinaryPrimitives.ReadUInt64LittleEndian(vector.InitialCounter));
				return cipher;
			}
			default:
			{
				throw new NotSupportedException(vector.Algorithm);
			}
		}
	}
}
