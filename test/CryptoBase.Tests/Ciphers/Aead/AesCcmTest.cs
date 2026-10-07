using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
using CryptoBase.Ciphers.Modes.Ccm;
using CryptoBase.Tests.Ciphers.Modes;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;
using BclAes = System.Security.Cryptography.Aes;

namespace CryptoBase.Tests.Ciphers.Aead;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class AesCcmTest
{
	private const int MaxMessageLength = (1 << 24) - 1;

	public static IEnumerable<int> MessageLengths()
	{
		// Every final block length, then longer runs of full blocks.
		return [.. Enumerable.Range(0, 34), 127, 128, 129, 255, 256, 257, 4096, 4097];
	}

	public static IEnumerable<int> AssociatedDataLengths()
	{
		// The first block holds 14 bytes after a 2-byte length and 10 bytes after a 6-byte length.
		return [1, 13, 14, 15, 29, 30, 31, 0xFEFF, 0xFF00, 0xFF09, 0xFF0A, 0xFF0B, 0x10000];
	}

	// NIST SP 800-38C Appendix C example 4 validates the reference model's 6-byte associated data length encoding.
	[Test]
	public async Task ReferenceMatchesSp80038CLongAssociatedData()
	{
		byte[] key = Convert.FromHexString(@"404142434445464748494a4b4c4d4e4f");
		byte[] nonce = Convert.FromHexString(@"101112131415161718191a1b1c");
		byte[] associatedData = new byte[1 << 16];
		byte[] plaintext = Convert.FromHexString(@"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
		byte[] expectedTag = Convert.FromHexString(@"b4ac6bec93e8598e7f0dadbcea5b");

		for (int i = 0; i < associatedData.Length; ++i)
		{
			associatedData[i] = (byte)i;
		}

		(byte[] ciphertext, byte[] tag) = EncryptReference(key, nonce, plaintext, associatedData, expectedTag.Length);
		await Assert.That(ciphertext).IsEquivalentTo(Convert.FromHexString(@"69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72"), CollectionOrdering.Matching);
		await Assert.That(tag).IsEquivalentTo(expectedTag, CollectionOrdering.Matching);
	}

	[Test]
	[MatrixDataSource]
	public async Task MessagesMatchReference([Matrix(16, 24, 32)] int keyLength, [MatrixMethod<AesCcmTest>(nameof(MessageLengths))] int length)
	{
		byte[] key = CreateDeterministicSource(keyLength);
		byte[] nonce = CreateDeterministicSource(CcmMode128<AesCipher>.NonceSize);
		byte[] associatedData = CreateDeterministicSource(29);
		byte[] plaintext = CreateDeterministicSource(length);
		(byte[] expected, byte[] expectedTag) = EncryptReference(key, nonce, plaintext, associatedData);

		using (CcmMode128<AesCipher> cipher = CcmMode128<AesCipher>.Create(key))
		{
			await CcmTestUtils.AssertMessage(cipher, nonce, plaintext, associatedData, expected, expectedTag);
		}

		await AssertBuffered<CcmTag16>(key, nonce, plaintext, associatedData, expected, expectedTag);
	}

	[Test]
	[MatrixDataSource]
	public async Task AssociatedDataLengthEncodingMatchesReference([MatrixMethod<AesCcmTest>(nameof(AssociatedDataLengths))] int associatedDataLength)
	{
		byte[] key = CreateDeterministicSource(16);
		byte[] nonce = CreateDeterministicSource(CcmMode128<AesCipher>.NonceSize);
		byte[] associatedData = CreateDeterministicSource(associatedDataLength);
		byte[] plaintext = CreateDeterministicSource(17);
		(byte[] expected, byte[] expectedTag) = EncryptReference(key, nonce, plaintext, associatedData);
		using CcmMode128<AesCipher> cipher = CcmMode128<AesCipher>.Create(key);
		await CcmTestUtils.AssertMessage(cipher, nonce, plaintext, associatedData, expected, expectedTag);
	}

	[Test]
	public async Task MessageLengthIsLimitedByTheLengthField()
	{
		byte[] key = CreateDeterministicSource(16);
		byte[] nonce = CreateDeterministicSource(CcmMode128<AesCipher>.NonceSize);
		byte[] plaintext = CreateDeterministicSource(MaxMessageLength + 1);
		byte[] ciphertext = new byte[plaintext.Length];
		byte[] tag = new byte[CcmMode128<AesCipher>.TagSize];
		using CcmMode128<AesCipher> cipher = CcmMode128<AesCipher>.Create(key);
		PrepareDestination(ciphertext);
		PrepareDestination(tag);

		await Assert.That(() => cipher.Encrypt(nonce, plaintext, ciphertext, tag)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("source");
		await Assert.That(IsUnchanged(ciphertext)).IsTrue();
		await Assert.That(IsUnchanged(tag)).IsTrue();
		await Assert.That(() => cipher.TryDecrypt(nonce, plaintext, tag, ciphertext)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("source");
		await Assert.That(IsUnchanged(ciphertext)).IsTrue();

		cipher.Encrypt(nonce, plaintext.AsSpan(0, MaxMessageLength), ciphertext, tag);
		await Assert.That(ciphertext[MaxMessageLength]).IsEqualTo(DestinationSentinel);

		// The final partial block uses counter 2^20, which must not carry into the nonce.
		const int finalOffset = MaxMessageLength & -16;
		byte[] finalKeyStream = EncryptBlocks(key, [2, .. nonce, 0x10, 0x00, 0x00]);
		byte[] expectedFinalBlock = new byte[MaxMessageLength - finalOffset];

		for (int i = 0; i < expectedFinalBlock.Length; ++i)
		{
			expectedFinalBlock[i] = (byte)(plaintext[finalOffset + i] ^ finalKeyStream[i]);
		}

		await Assert.That(ciphertext.AsMemory(finalOffset, expectedFinalBlock.Length)).IsEquivalentTo(expectedFinalBlock, CollectionOrdering.Matching);

		if (AesCcm.IsSupported)
		{
			(byte[] expected, byte[] expectedTag) = EncryptBcl(key, nonce, plaintext.AsSpan(0, MaxMessageLength).ToArray());
			await Assert.That(ciphertext.AsMemory(0, MaxMessageLength).Span.SequenceEqual(expected)).IsTrue();
			await Assert.That(tag).IsEquivalentTo(expectedTag, CollectionOrdering.Matching);
		}

		byte[] recovered = new byte[MaxMessageLength];
		await Assert.That(cipher.TryDecrypt(nonce, ciphertext.AsSpan(0, MaxMessageLength), tag, recovered)).IsTrue();
		await Assert.That(recovered.AsSpan().SequenceEqual(plaintext.AsSpan(0, MaxMessageLength))).IsTrue();
	}

	internal static (byte[] Ciphertext, byte[] Tag) EncryptReference(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData, int tagLength = 16)
	{
		return CcmReference.Encrypt(blocks => EncryptBlocks(key, blocks), nonce, plaintext, associatedData, tagLength);
	}

	private static byte[] EncryptBlocks(byte[] key, byte[] blocks)
	{
		using BclAes aes = BclAes.Create();
		aes.Key = key;
		return aes.EncryptEcb(blocks, PaddingMode.None);
	}

	private static (byte[] Ciphertext, byte[] Tag) EncryptBcl(byte[] key, byte[] nonce, byte[] plaintext)
	{
		using AesCcm aes = new(key);
		byte[] ciphertext = new byte[plaintext.Length];
		byte[] tag = new byte[CcmMode128<AesCipher>.TagSize];
		aes.Encrypt(nonce, plaintext, ciphertext, tag);
		return (ciphertext, tag);
	}

	// Exercises the path used when AES-NI and ARM64 AES are unavailable.
	internal static async Task AssertBuffered<TTag>(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData, byte[] expected, byte[] expectedTag) where TTag : struct, ICcmTag
	{
		(byte[] ciphertext, byte[] tag, bool authenticated, byte[] recovered, bool forged, byte[] rejected) = TransformBuffered<TTag>(key, nonce, plaintext, associatedData);
		await Assert.That(ciphertext).IsEquivalentTo(expected, CollectionOrdering.Matching);
		await Assert.That(tag).IsEquivalentTo(expectedTag, CollectionOrdering.Matching);
		await Assert.That(authenticated).IsTrue();
		await Assert.That(recovered).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
		await Assert.That(forged).IsFalse();
		await Assert.That(rejected.AsSpan().ContainsAnyExcept((byte)0)).IsFalse();
	}

	private static (byte[] Ciphertext, byte[] Tag, bool Authenticated, byte[] Plaintext, bool Forged, byte[] Rejected) TransformBuffered<TTag>(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData) where TTag : struct, ICcmTag
	{
		using AesCipher aes = AesCipher.Create(key);
		byte[] buffer = new byte[BufferedCcmBlockEncryptor<AesCipher>.BufferSize];
		BufferedCcmBlockEncryptor<AesCipher> encryptor = new(aes, buffer);
		byte[] ciphertext = new byte[plaintext.Length];
		byte[] tag = new byte[TTag.Size];
		CcmUtils.Encrypt<TTag, BufferedCcmBlockEncryptor<AesCipher>>(encryptor, nonce, plaintext, ciphertext, tag, associatedData);

		byte[] recovered = new byte[plaintext.Length];
		bool authenticated = CcmUtils.TryDecrypt<TTag, BufferedCcmBlockEncryptor<AesCipher>>(encryptor, nonce, ciphertext, tag, recovered, associatedData);

		byte[] badTag = tag.ToArray();
		badTag[0] ^= 1;
		byte[] rejected = new byte[plaintext.Length];
		rejected.AsSpan().Fill(DestinationSentinel);
		bool forged = CcmUtils.TryDecrypt<TTag, BufferedCcmBlockEncryptor<AesCipher>>(encryptor, nonce, ciphertext, badTag, rejected, associatedData);
		return (ciphertext, tag, authenticated, recovered, forged, rejected);
	}

	private static bool IsUnchanged(byte[] buffer)
	{
		return !buffer.AsSpan().ContainsAnyExcept(DestinationSentinel);
	}
}
