using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Blocks.SM4;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Blocks;

[GenerateGenericTest(typeof(AesCipher))]
[GenerateGenericTest(typeof(SM4Cipher))]
public class BlockCipherContractTest<T> where T : IBlockCipher<T>
{
	[Test]
	[Arguments(false)]
	[Arguments(true)]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before the cipher is disposed.")]
	public async Task InvalidBuffersDoNotWrite(bool decrypt)
	{
		using T cipher = T.Create(CreateDeterministicSource(16));
		byte[] source = CreateDeterministicSource(64);
		byte[] output = new byte[64];
		PrepareDestination(output);

		foreach (int length in new[] { 0, 15, 17, 32 })
		{
			await Assert.That(() => Single(source.AsSpan(0, length), output)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("source");
			await Assert.That(output).All(static x => x is DestinationSentinel);
		}

		foreach (int length in new[] { 1, 15, 17, 31 })
		{
			await Assert.That(() => Batch(source.AsSpan(0, length), output)).ThrowsExactly<ArgumentException>().WithParameterName("source");
			await Assert.That(output).All(static x => x is DestinationSentinel);
		}

		await Assert.That(() => Single(source.AsSpan(0, 16), output.AsSpan(0, 15))).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
		await Assert.That(() => Batch(source, output.AsSpan(0, 63))).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
		await Assert.That(output).All(static x => x is DestinationSentinel);
		await Assert.That(() => Batch(output.AsSpan(0, 32), output.AsSpan(1, 32))).ThrowsExactly<ArgumentException>().WithParameterName("destination");
		await Assert.That(() => Batch(output.AsSpan(1, 32), output.AsSpan(0, 32))).ThrowsExactly<ArgumentException>().WithParameterName("destination");
		await Assert.That(output).All(static x => x is DestinationSentinel);

		return;

		void Single(ReadOnlySpan<byte> input, Span<byte> destination)
		{
			if (decrypt)
			{
				cipher.DecryptBlock(input, destination);
			}
			else
			{
				cipher.EncryptBlock(input, destination);
			}
		}

		void Batch(ReadOnlySpan<byte> input, Span<byte> destination)
		{
			if (decrypt)
			{
				cipher.DecryptBlocks(input, destination);
			}
			else
			{
				cipher.EncryptBlocks(input, destination);
			}
		}
	}
}
