using System.Security.Cryptography;
using BclAes = System.Security.Cryptography.Aes;

namespace CryptoBase.Tests.Ciphers.Blocks.Aes;

internal static class AesTestUtils
{
	public static byte[] TransformReference(BclAes reference, byte[] source, byte[] mask, bool decrypt, bool xorInput)
	{
		byte[] input = xorInput ? source.ToArray() : source;

		if (xorInput)
		{
			for (int i = 0; i < input.Length; ++i)
			{
				input[i] ^= mask[i];
			}
		}

		byte[] output = decrypt
			? reference.DecryptEcb(input, PaddingMode.None)
			: reference.EncryptEcb(input, PaddingMode.None);

		for (int i = 0; i < output.Length; ++i)
		{
			output[i] ^= mask[i];
		}

		return output;
	}
}
