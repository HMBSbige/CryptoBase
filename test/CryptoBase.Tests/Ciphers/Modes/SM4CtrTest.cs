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

	public static IEnumerable<string> InitialCounters()
	{
		return
		[
			"000102030405060708090A0BFFFFFFE1",
			"0001020304050607FFFFFFFFFFFFFFE1",
			"00010203FFFFFFFFFFFFFFFFFFFFFFE1",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE1",
			"0001020304050607FFFFFFFFFFFFFFE5",
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE5",
			"0001020304050607FFFFFFFFFFFFFFA9"
		];
	}

	[Test]
	[MatrixDataSource]
	public async Task BatchCarriesMatchScalarReference([MatrixMethod<SM4CtrTest>(nameof(InitialCounters))] string initialCounterHex, [Matrix(255, 256, 257, 512, 768, 1023, 1024, 1025, 1280, 1543, 1792, 2048, 4097)] int length, [Matrix] bool inPlace)
	{
		byte[] key = CreateDeterministicSource(16);
		byte[] counter = Convert.FromHexString(initialCounterHex);
		byte[] plaintext = CreateDeterministicSource(4097).AsSpan(0, length).ToArray();
		byte[] expected = CtrReference.Transform(counter, plaintext, counters => SM4Reference.Transform(key, counters));
		byte[] output = CreateGuardedBuffer(3, plaintext);
		using CtrMode128<SM4Cipher> cipher = CtrMode128<SM4Cipher>.Create(key, counter);

		ReadOnlySpan<byte> source = inPlace ? output.AsSpan(3, length) : plaintext;
		cipher.Xor(source, output.AsSpan(3));

		await AssertOutput(output, 3, expected);
	}

	[Test]
	[MatrixDataSource]
	public async Task TailsMatchScalarReference([Matrix(0, 1)] int batches, [MatrixRange<int>(1, 63)] int tailBlocks, [Matrix(0, 7)] int extraBytes, [Matrix] bool inPlace)
	{
		int length = (batches * 64 + tailBlocks) * 16 + extraBytes;
		// Wraps the low 96 bits halfway through the tail, so the carry crosses words inside a partial group.
		uint low = 0u - (uint)(batches * 64 + tailBlocks / 2);
		byte[] counter = [0, 1, 2, 3, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, (byte)(low >> 24), (byte)(low >> 16), (byte)(low >> 8), (byte)low];
		byte[] key = CreateDeterministicSource(16);
		byte[] plaintext = CreateDeterministicSource(length);
		byte[] expected = CtrReference.Transform(counter, plaintext, counters => SM4Reference.Transform(key, counters));
		byte[] output = CreateGuardedBuffer(3, plaintext);
		using CtrMode128<SM4Cipher> cipher = CtrMode128<SM4Cipher>.Create(key, counter);

		ReadOnlySpan<byte> source = inPlace ? output.AsSpan(3, length) : plaintext;
		cipher.Xor(source, output.AsSpan(3, length));
		await AssertOutput(output, 3, expected);

		// The counter after the tail must also be right.
		byte[] next = new byte[16];
		cipher.Xor(next, next);
		byte[] expectedNext = CtrReference.Transform(counter, new byte[length + 16], counters => SM4Reference.Transform(key, counters)).AsSpan(length).ToArray();
		await AssertOutput(next, expectedNext);
	}

	[Test]
	[MatrixDataSource]
	public async Task ContinuationMatchesScalarReference([MatrixMethod<SM4CtrTest>(nameof(InitialCounters))] string initialCounterHex, [Matrix] bool inPlace)
	{
		byte[] key = CreateDeterministicSource(16);
		byte[] counter = Convert.FromHexString(initialCounterHex);
		byte[] plaintext = CreateDeterministicSource(4097);
		byte[] expected = CtrReference.Transform(counter, plaintext, counters => SM4Reference.Transform(key, counters));
		byte[] output = CreateGuardedBuffer(5, plaintext);
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
