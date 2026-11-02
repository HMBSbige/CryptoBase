using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
using CryptoBase.Platform;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Platform;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class PlatformAesGcmTest
{
	[Test]
	[MatrixDataSource]
	public async Task MatchesManagedAcrossKeyAndMessageLengths([Matrix(16, 24, 32)] int keyLength, [Matrix(0, 1, 16, 257, 8191, 8192, 8193, 65537)] int length)
	{
		byte[] key = CreateDeterministicSource(keyLength);
		byte[] nonce = CreateDeterministicSource(PlatformAesGcm.NonceSize);
		byte[] associatedData = CreateDeterministicSource(13);
		byte[] plaintext = CreateDeterministicSource(length);
		byte[] expected = new byte[length];
		byte[] expectedTag = new byte[PlatformAesGcm.TagSize];

		using (GcmMode<AesCipher> managed = GcmMode<AesCipher>.Create(key))
		{
			managed.Encrypt(nonce, plaintext, expected, expectedTag, associatedData);
		}

		using PlatformAesGcm cipher = PlatformAesGcm.Create(key);
		byte[] ciphertext = new byte[length + 7];
		byte[] tag = new byte[PlatformAesGcm.TagSize];
		PrepareDestination(ciphertext);
		cipher.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
		await AssertOutput(ciphertext, expected);
		await AssertOutput(tag, expectedTag);

		byte[] decrypted = new byte[length + 7];
		PrepareDestination(decrypted);
		await Assert.That(cipher.TryDecrypt(nonce, expected, expectedTag, decrypted, associatedData)).IsTrue();
		await AssertOutput(decrypted, plaintext);
	}

	[Test]
	[Arguments(0)]
	[Arguments(15)]
	[Arguments(17)]
	[Arguments(31)]
	[Arguments(33)]
	public async Task InvalidKeyLengthsAreRejected(int keyLength)
	{
		byte[] key = CreateDeterministicSource(keyLength);
		await Assert.That(() => PlatformAesGcm.Create(key)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("key");
	}

	[Test]
	public async Task IsPreferredForNeedsVaesAndAvx512From8KiB()
	{
		bool vaes = X86Base.IsSupported && (X86Base.CpuId(7, 0).Ecx & 1 << 9) is not 0;
		bool preferred = vaes && Avx512BW.IsSupported && Avx512DQ.IsSupported && Avx512F.VL.IsSupported && Pclmulqdq.V512.IsSupported && AesGcm.IsSupported;

		using (Assert.Multiple())
		{
			await Assert.That(PlatformAesGcm.IsPreferredFor(0)).IsFalse();
			await Assert.That(PlatformAesGcm.IsPreferredFor(8191)).IsFalse();
			await Assert.That(PlatformAesGcm.IsPreferredFor(8192)).IsEqualTo(preferred);
			await Assert.That(PlatformAesGcm.IsPreferredFor(int.MaxValue)).IsEqualTo(preferred);
			await Assert.That(static () => PlatformAesGcm.IsPreferredFor(-1)).Throws<ArgumentOutOfRangeException>().WithParameterName("length");
		}
	}

	[Test]
	public async Task PlatformFailureClearsTheOutputAndDisposesTheInstance()
	{
		byte[] key = CreateDeterministicSource(32);
		byte[] nonce = CreateDeterministicSource(PlatformAesGcm.NonceSize);
		byte[] associatedData = CreateDeterministicSource(13);
		byte[] plaintext = CreateDeterministicSource(97);
		byte[] ciphertext = new byte[plaintext.Length];
		byte[] tag = new byte[PlatformAesGcm.TagSize];

		using (PlatformAesGcm reference = PlatformAesGcm.Create(key))
		{
			reference.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
		}

		byte[] destination = new byte[plaintext.Length];
		byte[] outputTag = new byte[PlatformAesGcm.TagSize];
		(Action<PlatformAesGcm> Operation, bool WritesTag)[] operations =
		[
			(cipher => cipher.Encrypt(nonce, plaintext, destination, outputTag, associatedData), true),
			(cipher => cipher.TryDecrypt(nonce, ciphertext, tag, destination, associatedData), false),
		];

		foreach ((Action<PlatformAesGcm> operation, bool writesTag) in operations)
		{
			using AesGcm working = new(key, PlatformAesGcm.TagSize);
			using PlatformAesGcm cipher = PlatformAesGcm.Create(key);

			// Make the next platform call fail.
			PlatformFields.AesGcm(cipher).Dispose();
			PrepareDestination(destination);
			PrepareDestination(outputTag);
			await Assert.That(() => operation(cipher)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(destination).All(static value => value is 0);
			await Assert.That(outputTag).All(value => value == (writesTag ? 0 : DestinationSentinel));

			// Working platform state does not revive the failed instance.
			PlatformFields.AesGcm(cipher) = working;
			PrepareDestination(destination);
			PrepareDestination(outputTag);
			await Assert.That(() => operation(cipher)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(destination).All(static value => value is DestinationSentinel);
			await Assert.That(outputTag).All(static value => value is DestinationSentinel);
		}
	}

	private static class PlatformFields
	{
		[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_aesGcm")]
		public static extern ref AesGcm AesGcm(PlatformAesGcm cipher);
	}
}
