using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes;
using CryptoBase.Tests.Ciphers.Blocks.SM4;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Modes;

public class SM4CtrTest
{
	[Test]
	[Arguments
	(
		"B7FAD2F367B9999C95E207CA2E16616D",
		"CBD328D0C128002C6A44384590E6DBC9",
		"5B0C121AD672AAFF1009FC4294584AED651748C3E15765834A914755DC7D7FDCE7E1EDB7C821570AA9199E9C923CC4AEF36E1D270DE0BE2CC70E81A981B4369A",
		"B4632B189DF350F6D21C143B6CC7D0A29392FB0FF92410FB231669CA43E1BCFB6348CF02EAB1DFB0CB6349329C7CF4F5CEF1336B990DC087C5165652DE22C731"
	)]
	public async Task KnownVector(string keyHex, string counterHex, string plaintextHex, string ciphertextHex)
	{
		byte[] key = Convert.FromHexString(keyHex);
		byte[] counter = Convert.FromHexString(counterHex);
		byte[] plaintext = Convert.FromHexString(plaintextHex);
		byte[] ciphertext = Convert.FromHexString(ciphertextHex);

		await VerifyStreamVector(CtrMode128<SM4Cipher>.Create(key, counter), plaintext, ciphertext);
	}

	[Test]
	[Arguments("000102030405060708090A0BFFFFFFE1")]
	[Arguments("0001020304050607FFFFFFFFFFFFFFE1")]
	[Arguments("00010203FFFFFFFFFFFFFFFFFFFFFFE1")]
	[Arguments("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE1")]
	[Arguments("0001020304050607FFFFFFFFFFFFFFE5")]
	[Arguments("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE5")]
	public async Task BatchCarriesAndContinuationMatchScalarReference(string initialCounterHex)
	{
		byte[] key = CreateDeterministicSource(16);
		byte[] counter = Convert.FromHexString(initialCounterHex);
		byte[] plaintext = CreateDeterministicSource(4097);
		byte[] expected = CtrReference.Transform(counter, plaintext, counters => SM4Reference.Transform(key, counters));

		foreach (int length in new[] { 255, 256, 257, 1023, 1024, 1025, 2048, 4097 })
		{
			foreach (bool inPlace in new[] { false, true })
			{
				byte[] output = CreateGuardedBuffer(3, length);
				plaintext.AsSpan(0, length).CopyTo(output.AsSpan(3));
				using CtrMode128<SM4Cipher> cipher = CtrMode128<SM4Cipher>.Create(key, counter);
				ReadOnlySpan<byte> source = inPlace ? output.AsSpan(3, length) : plaintext.AsSpan(0, length);
				cipher.Xor(source, output.AsSpan(3));
				await AssertOutput(output, 3, expected.AsSpan(0, length).ToArray());
			}
		}

		foreach (bool inPlace in new[] { false, true })
		{
			byte[] output = CreateGuardedBuffer(5, plaintext.Length);
			plaintext.CopyTo(output, 5);
			using CtrMode128<SM4Cipher> cipher = CtrMode128<SM4Cipher>.Create(key, counter);
			int offset = 0;

			foreach (int length in new[] { 1, 1040, 0, 1024, 15, 2017 })
			{
				ReadOnlySpan<byte> source = inPlace ? output.AsSpan(5 + offset, length) : plaintext.AsSpan(offset, length);
				cipher.Xor(source, output.AsSpan(5 + offset, length));
				offset += length;
			}

			await AssertOutput(output, 5, expected);
		}
	}
}
