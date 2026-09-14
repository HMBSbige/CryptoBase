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
			496, 512, 528, // Below the SIMD threshold, at it, and with a remaining full block.
			529, 543, // SIMD followed by the shortest and longest stealing tails.
			2048, 2065, // A full tweak buffer, then stealing immediately after it.
			2560, 2561, 4097 // A second batch using SIMD, fallback, or SIMD plus a remainder.
		];
	}

	[Test]
	[GenerateGenericTest(typeof(AesCipher))]
	[GenerateGenericTest(typeof(SM4Cipher))]
	[MethodDataSource(nameof(BatchLengths))]
	public async Task BatchAndStealingBoundariesMatchScalarTweaks<TCipher>(int length) where TCipher : IBlockCipher<TCipher>
	{
		await VerifyScalarTweaks<TCipher>(16, length);
	}

	[Test]
	[Arguments(512)]
	[Arguments(4097)]
	public async Task Aes256BatchAndStealingBoundariesMatchScalarTweaks(int length)
	{
		await VerifyScalarTweaks<AesCipher>(32, length);
	}

	private static async Task VerifyScalarTweaks<TCipher>(int keyLength, int length) where TCipher : IBlockCipher<TCipher>
	{
		byte[] key = CreateDeterministicSource(keyLength * 2);
		byte[] plaintext = CreateDeterministicSource(length);
		byte[] iv = new byte[16];
		byte[] initialTweak = new byte[16];
		initialTweak.AsSpan().Fill(0xFF);
		using TCipher dataCipher = TCipher.Create(key.AsSpan(0, keyLength));
		using TCipher tweakCipher = TCipher.Create(key.AsSpan(keyLength));
		// Force carries across both 64-bit halves and the reduction boundary.
		tweakCipher.DecryptBlock(initialTweak, iv);
		byte[] expected = EncryptWithScalarTweaks(dataCipher, initialTweak, plaintext);
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

	private static byte[] EncryptWithScalarTweaks<TCipher>(TCipher cipher, byte[] initialTweak, byte[] plaintext) where TCipher : IBlockCipher<TCipher>
	{
		byte[] tweak = initialTweak.ToArray();
		byte[] output = new byte[plaintext.Length];
		int tail = plaintext.Length % 16;
		int ordinaryLength = tail is 0 ? plaintext.Length : plaintext.Length - tail - 16;
		int offset = 0;

		for (; offset < ordinaryLength; offset += 16)
		{
			EncryptBlock(cipher, tweak, plaintext.AsSpan(offset, 16), output.AsSpan(offset, 16));
			MultiplyScalar(tweak);
		}

		if (tail is not 0)
		{
			Span<byte> last = stackalloc byte[16];
			EncryptBlock(cipher, tweak, plaintext.AsSpan(offset, 16), last);
			last.Slice(0, tail).CopyTo(output.AsSpan(offset + 16));
			plaintext.AsSpan(offset + 16).CopyTo(last);
			MultiplyScalar(tweak);
			EncryptBlock(cipher, tweak, last, output.AsSpan(offset, 16));
		}

		return output;
	}

	private static void EncryptBlock<TCipher>(TCipher cipher, byte[] tweak, ReadOnlySpan<byte> source, Span<byte> destination) where TCipher : IBlockCipher<TCipher>
	{
		Span<byte> block = stackalloc byte[16];

		for (int i = 0; i < 16; ++i)
		{
			block[i] = (byte)(source[i] ^ tweak[i]);
		}

		cipher.EncryptBlock(block, block);

		for (int i = 0; i < 16; ++i)
		{
			destination[i] = (byte)(block[i] ^ tweak[i]);
		}
	}

	private static void MultiplyScalar(byte[] tweak)
	{
		int carry = 0;

		for (int i = 0; i < 16; ++i)
		{
			int value = tweak[i];
			tweak[i] = (byte)(value << 1 | carry);
			carry = value >> 7;
		}

		if (carry is not 0)
		{
			tweak[0] ^= 0x87;
		}
	}
}
