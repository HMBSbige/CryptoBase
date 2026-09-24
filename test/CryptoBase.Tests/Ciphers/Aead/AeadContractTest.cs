using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Aead;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes.Gcm;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Aead;

[InheritsTests]
public class AesGcmContractTest() : AeadContractTest<GcmMode128<AesCipher>>(32);

[InheritsTests]
public class SM4GcmContractTest() : AeadContractTest<GcmMode128<SM4Cipher>>(16);

[InheritsTests]
public class ChaCha20Poly1305ContractTest() : AeadContractTest<ChaCha20Poly1305Cipher>(32);

[InheritsTests]
public class XChaCha20Poly1305ContractTest() : AeadContractTest<XChaCha20Poly1305Cipher>(32);

public abstract class AeadContractTest<T>(int keyLength) where T : IAeadCipher<T>
{
	[Test]
	[MatrixDataSource]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before the cipher is disposed.")]
	public async Task InvalidArgumentsDoNotWriteAndAllowRetry([Matrix(0, 1, 257, 4097)] int length)
	{
		using T cipher = T.Create(CreateDeterministicSource(keyLength));
		byte[] nonce = CreateDeterministicSource(T.NonceSize);
		byte[] aad = CreateDeterministicSource(19);
		byte[] plaintext = CreateDeterministicSource(length);
		byte[] ciphertext = new byte[length + 7];
		byte[] tag = new byte[T.TagSize];
		PrepareDestination(ciphertext);
		await Assert.That(() => cipher.Encrypt(nonce.AsSpan(1), plaintext, ciphertext, tag, aad)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("nonce");
		await Assert.That(ciphertext).All(static x => x is DestinationSentinel);
		await Assert.That(() => cipher.TryDecrypt(nonce, plaintext, tag.AsSpan(1), ciphertext, aad)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("tag");
		await Assert.That(ciphertext).All(static x => x is DestinationSentinel);

		if (length > 0)
		{
			await Assert.That(() => cipher.Encrypt(nonce, plaintext, ciphertext.AsSpan(0, length - 1), tag, aad)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
			await Assert.That(ciphertext).All(static x => x is DestinationSentinel);
			await Assert.That(() => cipher.TryDecrypt(nonce, plaintext, tag, ciphertext.AsSpan(0, length - 1), aad)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
			await Assert.That(ciphertext).All(static x => x is DestinationSentinel);
		}

		cipher.Encrypt(nonce, plaintext, ciphertext, tag, aad);
		await Assert.That(ciphertext.AsMemory(length)).All(static x => x is DestinationSentinel);
		byte[] output = new byte[length + 7];
		PrepareDestination(output);
		await Assert.That(cipher.TryDecrypt(nonce, ciphertext.AsSpan(0, length), tag, output, aad)).IsTrue();
		await AssertOutput(output, plaintext);
	}

	[Test]
	[MatrixDataSource]
	public async Task SuccessfulOperationsPreserveTailAndSupportInPlace([Matrix(0, 1, 257, 4097)] int length)
	{
		using T cipher = T.Create(CreateDeterministicSource(keyLength));
		byte[] nonce = CreateDeterministicSource(T.NonceSize);
		byte[] aad = CreateDeterministicSource(19);
		byte[] plaintext = CreateDeterministicSource(length);
		byte[] ciphertext = new byte[length + 7];
		byte[] tag = new byte[T.TagSize];
		PrepareDestination(ciphertext);
		cipher.Encrypt(nonce, plaintext, ciphertext, tag, aad);
		await Assert.That(ciphertext.AsMemory(length)).All(static x => x is DestinationSentinel);

		byte[] output = new byte[length + 7];
		PrepareDestination(output);
		await Assert.That(cipher.TryDecrypt(nonce, ciphertext.AsSpan(0, length), tag, output, aad)).IsTrue();
		await AssertOutput(output, plaintext);

		byte[] inPlaceTag = new byte[T.TagSize];
		cipher.Encrypt(nonce, output.AsSpan(0, length), output, inPlaceTag, aad);
		await Assert.That(output).IsEquivalentTo(ciphertext, CollectionOrdering.Matching);
		await Assert.That(inPlaceTag).IsEquivalentTo(tag, CollectionOrdering.Matching);

		await Assert.That(cipher.TryDecrypt(nonce, output.AsSpan(0, length), inPlaceTag, output, aad)).IsTrue();
		await AssertOutput(output, plaintext);
	}

	[Test]
	public async Task EveryTagBitIsAuthenticated()
	{
		const int length = 257;
		using T cipher = T.Create(CreateDeterministicSource(keyLength));
		byte[] nonce = CreateDeterministicSource(T.NonceSize);
		byte[] aad = CreateDeterministicSource(29);
		byte[] plaintext = CreateDeterministicSource(length);
		byte[] ciphertext = new byte[length];
		byte[] tag = new byte[T.TagSize];
		byte[] output = new byte[length + 7];
		cipher.Encrypt(nonce, plaintext, ciphertext, tag, aad);

		for (int index = 0; index < tag.Length; ++index)
		{
			for (int bit = 0; bit < 8; ++bit)
			{
				tag[index] ^= (byte)(1 << bit);
				PrepareDestination(output);
				await Assert.That(cipher.TryDecrypt(nonce, ciphertext, tag, output, aad)).IsFalse();
				await Assert.That(output.AsMemory(0, length)).All(static x => x is 0);
				await Assert.That(output.AsMemory(length)).All(static x => x is DestinationSentinel);
				tag[index] ^= (byte)(1 << bit);
			}
		}

		await Assert.That(cipher.TryDecrypt(nonce, ciphertext, tag, output, aad)).IsTrue();
		await AssertOutput(output, plaintext);
	}

	[Test]
	[MatrixDataSource]
	public async Task AuthenticationFailureClearsOnlyOutputPrefix([Matrix(0, 1, 257, 4097)] int length)
	{
		using T cipher = T.Create(CreateDeterministicSource(keyLength));
		byte[] nonce = CreateDeterministicSource(T.NonceSize);
		byte[] aad = CreateDeterministicSource(19);
		byte[] plaintext = CreateDeterministicSource(length);
		byte[] ciphertext = new byte[length + 7];
		byte[] tag = new byte[T.TagSize];
		PrepareDestination(ciphertext);
		cipher.Encrypt(nonce, plaintext, ciphertext, tag, aad);
		byte[] output = new byte[length + 7];

		for (int target = 0; target < 4; ++target)
		{
			if (target is 3 && length is 0)
			{
				continue;
			}

			byte[] badNonce = nonce.ToArray();
			byte[] badAad = aad.ToArray();
			byte[] badTag = tag.ToArray();
			byte[] badCiphertext = ciphertext.ToArray();
			byte[] tampered = target switch { 0 => badNonce, 1 => badAad, 2 => badTag, _ => badCiphertext };
			tampered[0] ^= 1;
			PrepareDestination(output);
			await Assert.That(cipher.TryDecrypt(badNonce, badCiphertext.AsSpan(0, length), badTag, output, badAad)).IsFalse();
			await Assert.That(output.AsMemory(0, length)).All(static x => x is 0);
			await Assert.That(output.AsMemory(length)).All(static x => x is DestinationSentinel);
			await Assert.That(cipher.TryDecrypt(badNonce, badCiphertext.AsSpan(0, length), badTag, badCiphertext, badAad)).IsFalse();
			await Assert.That(badCiphertext.AsMemory(0, length)).All(static x => x is 0);
			await Assert.That(badCiphertext.AsMemory(length)).All(static x => x is DestinationSentinel);
		}

		await Assert.That(cipher.TryDecrypt(nonce, ciphertext.AsSpan(0, length), tag, ciphertext, aad)).IsTrue();
		await AssertOutput(ciphertext, plaintext);
	}
}
