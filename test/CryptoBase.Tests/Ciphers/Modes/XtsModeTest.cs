using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Modes;

public class XtsModeTest
{
	public static IEnumerable<int> BatchLengths()
	{
		return
		[
			17, 31, 33, 47, 127, 129, 145,
			496, 512, 528,
			529, 543,
			2047, 2048, 2049, 2063, 2065,
			2560, 2561, 4097
		];
	}

	[Test]
	[GenerateGenericTest(typeof(AesCipher))]
	[GenerateGenericTest(typeof(SM4Cipher))]
	[MethodDataSource(nameof(BatchLengths))]
	public Task BatchAndStealingBoundariesMatchScalarTweaks<TCipher>(int length) where TCipher : IBlockCipher<TCipher>
	{
		return VerifyScalarTweaks<TCipher>(16, length);
	}

	[Test]
	[Arguments(512)]
	[Arguments(4097)]
	public Task Aes256BatchAndStealingBoundariesMatchScalarTweaks(int length)
	{
		return VerifyScalarTweaks<AesCipher>(32, length);
	}

	private static async Task VerifyScalarTweaks<TCipher>(int keyLength, int length) where TCipher : IBlockCipher<TCipher>
	{
		byte[] key = CreateDeterministicSource(keyLength * 2);
		byte[] plaintext = CreateDeterministicSource(length);
		byte[] iv = new byte[16];
		byte[] initialTweak = new byte[16];
		initialTweak.AsSpan().Fill(0xFF);
		using TCipher tweakCipher = TCipher.Create(key.AsSpan(keyLength));
		// Force carries across both 64-bit halves and the reduction boundary.
		tweakCipher.DecryptBlock(initialTweak, iv);
		byte[] expected = XtsReference.Transform(initialTweak, plaintext, false, block =>
		{
			using TCipher dataCipher = TCipher.Create(key.AsSpan(0, keyLength));
			dataCipher.EncryptBlock(block, block);
			return block;
		});
		using XtsMode<TCipher> cipher = XtsMode<TCipher>.Create(key);
		byte[] output = new byte[length + 7];
		PrepareDestination(output);

		cipher.Encrypt(iv, plaintext, output);
		await AssertOutput(output, expected);
		cipher.Decrypt(iv, expected, output);
		await AssertOutput(output, plaintext);
		plaintext.CopyTo(output, 0);
		cipher.Encrypt(iv, output.AsSpan(0, length), output);
		await AssertOutput(output, expected);
		cipher.Decrypt(iv, output.AsSpan(0, length), output);
		await AssertOutput(output, plaintext);
	}
}
