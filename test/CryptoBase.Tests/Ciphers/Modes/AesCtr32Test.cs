using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
using CryptoBase.Ciphers.Modes.Ctr;
using System.Buffers.Binary;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Modes;

public class AesCtr32Test
{
	[Test]
	[MatrixDataSource]
	public async Task CountersWrapWithoutChangingNonce([Matrix(16, 24, 32)] int keyLength, [Matrix(2u, 0xFFFFFFFEu)] uint initialCounter, [Matrix(32, 48, 64, 128, 256, 4096)] int fullLength)
	{
		if (!AesCipherX86.IsSupported && !AesCipherArm.IsSupported)
		{
			Skip.Test("Hardware AES is required.");
		}

		const int prefixLength = 3;
		byte[] key = CreateDeterministicSource(keyLength);
		byte[] initial = CreateDeterministicSource(16);
		BinaryPrimitives.WriteUInt32BigEndian(initial.AsSpan(12), initialCounter);
		using AesCipher cipher = AesCipher.Create(key);

		foreach (int tailLength in new[] { 0, 1, 15 })
		{
			int length = fullLength + tailLength;
			byte[] plaintext = CreateDeterministicSource(length);
			byte[] input = new byte[prefixLength + length];
			plaintext.CopyTo(input, prefixLength);
			byte[] expected = CtrReference.Transform
			(
				initial, plaintext, counters =>
				{
					using Aes reference = Aes.Create();
					reference.Key = key;
					return reference.EncryptEcb(counters, PaddingMode.None);
				}, counterBits: 32
			);

			foreach (bool inPlace in new[] { false, true })
			{
				byte[] output = CreateGuardedBuffer(prefixLength, length);
				plaintext.CopyTo(output, prefixLength);
				Vector128<byte> counter = Vector128.Create(initial);
				ReadOnlySpan<byte> source = inPlace ? output.AsSpan(0, prefixLength + length) : input;
				int processed = BlockModeDispatch.XorCtr<AesCipher, CtrIncrementer32>(cipher, ref counter, source.Slice(prefixLength), output.AsSpan(prefixLength));
				CtrBlocks<AesCipher, CtrIncrementer32>.Xor(cipher, ref counter, source.Slice(prefixLength + processed), output.AsSpan(prefixLength + processed));
				await Assert.That(processed).IsEqualTo(fullLength);
				await AssertOutput(output, prefixLength, expected);
				byte[] expectedCounter = (byte[])initial.Clone();
				BinaryPrimitives.WriteUInt32BigEndian(expectedCounter.AsSpan(12), initialCounter + (uint)((length + 15) / 16));
				await Assert.That(counter).IsEqualTo(Vector128.Create(expectedCounter));
			}
		}
	}
}
