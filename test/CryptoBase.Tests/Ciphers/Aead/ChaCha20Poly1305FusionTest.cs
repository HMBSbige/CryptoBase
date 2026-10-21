using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Aead;
using CryptoBase.Ciphers.Streams;
using CryptoBase.Macs.Poly1305;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Aead;

public class ChaCha20Poly1305FusionTest
{
	public enum AuthenticationMutation
	{
		FirstTagByte,
		LastTagByte,
		AssociatedData,
		FirstCiphertextByte,
		CiphertextAtBatchBoundary,
		LastCiphertextByte,
	}

	public static IEnumerable<int> KernelLengths()
	{
		return [960, 961, 1023, 1024, 1025, 1087, 1088, 1215, 1216, 1472, 1535, 1536, 1984, 2047, 3072, 4111, 65537];
	}

	// Kernel runs start after prefixes of these lengths, which encryption has not hashed yet.
	public static IEnumerable<int> PrefixLengths()
	{
		return [0, 64, 192, 448, 960];
	}

	[Test]
	[GenerateGenericTest(typeof(ChaCha20Poly1305Cipher))]
	[GenerateGenericTest(typeof(XChaCha20Poly1305Cipher))]
	[MatrixDataSource]
	public async Task AssociatedDataMayOverlapFusedDestination<TCipher>([Matrix(193, 449, 961, 1500, 1984, 3072, 16384)] int length) where TCipher : IAeadCipher<TCipher>
	{
		using TCipher cipher = TCipher.Create(CreateDeterministicSource(32));
		byte[] nonce = CreateDeterministicSource(TCipher.NonceSize);
		byte[] aad = CreateDeterministicSource(29);
		byte[] plaintext = CreateDeterministicSource(length);
		byte[] ciphertext = new byte[length], output = new byte[length];
		byte[] tag = new byte[TCipher.TagSize], actualTag = new byte[TCipher.TagSize];
		cipher.Encrypt(nonce, plaintext, ciphertext, tag, aad);

		aad.CopyTo(output, 0);
		cipher.Encrypt(nonce, plaintext, output, actualTag, output.AsSpan(0, aad.Length));
		await Assert.That(output).IsEquivalentTo(ciphertext, CollectionOrdering.Matching);
		await Assert.That(actualTag).IsEquivalentTo(tag, CollectionOrdering.Matching);

		aad.CopyTo(output, 0);
		await Assert.That(cipher.TryDecrypt(nonce, ciphertext, tag, output, output.AsSpan(0, aad.Length))).IsTrue();
		await Assert.That(output).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
	}

	[Test]
	[GenerateGenericTest(typeof(ChaCha20Poly1305Cipher))]
	[GenerateGenericTest(typeof(XChaCha20Poly1305Cipher))]
	[MatrixDataSource]
	public async Task AuthenticationFailureClearsOnlyOutputAndAllowsRetry<TCipher>
	(
		[Matrix(449, 961, 1024, 1500, 1984, 2048, 2049, 3072, 8192, 16384, 16385, 65535, 65536, 65537, 131073)] int length,
		[Matrix] AuthenticationMutation mutation
	)
		where TCipher : IAeadCipher<TCipher>
	{
		using TCipher cipher = TCipher.Create(CreateDeterministicSource(32));
		byte[] nonce = CreateDeterministicSource(TCipher.NonceSize);
		byte[] aad = CreateDeterministicSource(29);
		byte[] plaintext = CreateDeterministicSource(length);
		byte[] ciphertext = new byte[length];
		byte[] tag = new byte[TCipher.TagSize];
		cipher.Encrypt(nonce, plaintext, ciphertext, tag, aad);

		byte[] input = ciphertext.ToArray(), suppliedTag = tag.ToArray(), suppliedAad = aad.ToArray();
		(byte[] target, int offset) = mutation switch
		{
			AuthenticationMutation.FirstTagByte => (suppliedTag, 0),
			AuthenticationMutation.LastTagByte => (suppliedTag, suppliedTag.Length - 1),
			AuthenticationMutation.AssociatedData => (suppliedAad, 0),
			AuthenticationMutation.FirstCiphertextByte => (input, 0),
			AuthenticationMutation.CiphertextAtBatchBoundary => (input, 448),
			AuthenticationMutation.LastCiphertextByte => (input, length - 1),
			_ => throw new ArgumentOutOfRangeException(nameof(mutation)),
		};
		target[offset] ^= 1;

		byte[] inputBefore = input.ToArray();
		byte[] guarded = CreateGuardedBuffer(17, length, 17);
		await Assert.That(cipher.TryDecrypt(nonce, input, suppliedTag, guarded.AsSpan(17, length), suppliedAad)).IsFalse();
		await AssertOutput(guarded, 17, new byte[length]);
		await Assert.That(input).IsEquivalentTo(inputBefore, CollectionOrdering.Matching);

		await Assert.That(cipher.TryDecrypt(nonce, input, suppliedTag, input, suppliedAad)).IsFalse();
		await Assert.That(input).All(static value => value is 0);

		byte[] restored = new byte[length];
		await Assert.That(cipher.TryDecrypt(nonce, ciphertext, tag, restored, aad)).IsTrue();
		await Assert.That(restored).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
	}

	[Test]
	[GenerateGenericTest(typeof(ChaCha20Poly1305Cipher))]
	[GenerateGenericTest(typeof(XChaCha20Poly1305Cipher))]
	[MatrixDataSource]
	public async Task ReusedInstanceMatchesFreshInstances<TCipher>([Matrix(0, 13, 4097)] int associatedDataLength) where TCipher : IAeadCipher<TCipher>
	{
		byte[] key = CreateDeterministicSource(32);
		byte[] nonce = CreateDeterministicSource(TCipher.NonceSize);
		byte[] associatedData = CreateDeterministicSource(associatedDataLength);
		using TCipher cipher = TCipher.Create(key);

		// Keep the sequence in one test to exercise state reset across message lengths and buffer modes.
		foreach ((int length, bool inPlace) in ChaCha20Poly1305Test.MessageCases())
		{
			byte[] plaintext = CreateDeterministicSource(length);
			byte[] expectedCiphertext = new byte[length];
			byte[] expectedTag = new byte[TCipher.TagSize];
			using TCipher fresh = TCipher.Create(key);
			fresh.Encrypt(nonce, plaintext, expectedCiphertext, expectedTag, associatedData);

			await ChaCha20Poly1305Test.VerifyEncryptAndDecrypt(cipher, nonce, plaintext, associatedData, inPlace, expectedCiphertext, expectedTag);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task Vector512KernelMatchesSeparatePasses([MatrixMethod<ChaCha20Poly1305FusionTest>(nameof(KernelLengths))] int length, [MatrixMethod<ChaCha20Poly1305FusionTest>(nameof(PrefixLengths))] int prefixLength, [Matrix] bool nearCounterLimit)
	{
		if (!ChaCha20Utils.CanFusePoly1305<Poly1305Avx512>())
		{
			Skip.Test("The AVX-512 ChaCha20-Poly1305 kernel is not used here.");
		}

		Random random = new(8439 + length);
		byte[] key = new byte[32];
		byte[] nonce = new byte[12];
		byte[] poly1305Key = new byte[32];
		byte[] associatedData = new byte[13];
		byte[] plaintext = new byte[length];
		random.NextBytes(key);
		random.NextBytes(nonce);
		random.NextBytes(poly1305Key);
		random.NextBytes(associatedData);
		random.NextBytes(plaintext);

		uint counter = nearCounterLimit ? uint.MaxValue - (uint)((length + 63) / 64) : 1;
		if (nearCounterLimit)
		{
			poly1305Key.AsSpan().Fill(255);
		}

		byte[] expectedCiphertext = new byte[length];
		byte[] expectedTag = new byte[16];
		ComputeSeparately(key, nonce, poly1305Key, associatedData, plaintext, expectedCiphertext, expectedTag, counter);

		byte[] tag = new byte[16];
		byte[] guarded = CreateGuardedBuffer(17, length, 17);
		int processed = ComputeFused(key, nonce, poly1305Key, associatedData, plaintext, guarded.AsSpan(17, length), tag, counter, prefixLength);
		await Assert.That(processed).IsEqualTo(length);
		await AssertOutput(guarded, 17, expectedCiphertext);
		await Assert.That(tag).IsEquivalentTo(expectedTag, CollectionOrdering.Matching);

		plaintext.CopyTo(guarded, 17);
		ComputeFused(key, nonce, poly1305Key, associatedData, guarded.AsSpan(17, length), guarded.AsSpan(17, length), tag, counter, prefixLength);
		await AssertOutput(guarded, 17, expectedCiphertext);
		await Assert.That(tag).IsEquivalentTo(expectedTag, CollectionOrdering.Matching);

		guarded = CreateGuardedBuffer(17, length, 17);
		int decrypted = ComputeFused(key, nonce, poly1305Key, associatedData, expectedCiphertext, guarded.AsSpan(17, length), tag, counter, prefixLength, decrypt: true);
		await Assert.That(decrypted).IsGreaterThan(length - 2 * 128);
		await AssertOutput(guarded, 17, plaintext);
		await Assert.That(tag).IsEquivalentTo(expectedTag, CollectionOrdering.Matching);

		expectedCiphertext.CopyTo(guarded, 17);
		ComputeFused(key, nonce, poly1305Key, associatedData, guarded.AsSpan(17, length), guarded.AsSpan(17, length), tag, counter, prefixLength, decrypt: true);
		await AssertOutput(guarded, 17, plaintext);
		await Assert.That(tag).IsEquivalentTo(expectedTag, CollectionOrdering.Matching);
	}

	private static void ComputeSeparately(byte[] key, byte[] nonce, byte[] poly1305Key, byte[] associatedData, byte[] plaintext, byte[] ciphertext, byte[] tag, uint counter)
	{
		using ChaCha20Cipher cipher = new(key, nonce);
		cipher.SetCounter(counter);
		cipher.Xor(plaintext, ciphertext);

		Poly1305Software state = default;
		Poly1305Software.Initialize(ref state, poly1305Key);
		state.AppendPaddedSegment(associatedData);
		state.AppendPaddedSegment(ciphertext);
		state.WriteMac(tag);
	}

	// Decryption hashes the prefix before the kernel; encryption hashes from the start of the message.
	private static int ComputeFused(byte[] key, byte[] nonce, byte[] poly1305Key, byte[] associatedData, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag, uint counter, int prefixLength, bool decrypt = false)
	{
		int hashed = decrypt ? prefixLength : 0;
		using ChaCha20Cipher cipher = new(key, nonce);
		cipher.SetCounter(counter);

		Poly1305Avx512 state = default;
		Poly1305Avx512.Initialize(ref state, poly1305Key);
		// A non-zero accumulator checks the conversion into and out of the kernel.
		state.AppendPaddedSegment(associatedData);
		if (decrypt)
		{
			state.AppendMessage(plaintext.Slice(0, hashed));
		}
		cipher.Xor(plaintext.Slice(0, prefixLength), ciphertext.Slice(0, prefixLength));
		int processed = cipher.XorChunksAndAppendPoly1305(plaintext, ciphertext, ref state, prefixLength, ref hashed, decrypt);
		if (decrypt)
		{
			state.AppendPaddedSegment(plaintext.Slice(hashed));
		}
		cipher.Xor(plaintext.Slice(processed), ciphertext.Slice(processed));
		if (!decrypt)
		{
			state.AppendPaddedSegment(ciphertext.Slice(hashed));
		}
		state.WriteMac(tag);
		return processed;
	}
}
