using CryptoBase.Abstractions.Ciphers;

namespace CryptoBase.Tests;

public static class TestUtils
{
	public const byte DestinationSentinel = 0xA5;

	public static byte[] CreateDeterministicSource(int length)
	{
		byte[] source = new byte[length];

		for (int i = 0; i < source.Length; ++i)
		{
			source[i] = (byte)(i * 131 + length * 17 + 7);
		}

		return source;
	}

	public static byte[] Concat(ReadOnlySpan<byte> first, ReadOnlySpan<byte> second)
	{
		byte[] result = new byte[first.Length + second.Length];
		first.CopyTo(result);
		second.CopyTo(result.AsSpan().Slice(first.Length));
		return result;
	}

	public static void PrepareDestination(Span<byte> destination)
	{
		destination.Fill(DestinationSentinel);
	}

	public static async Task AssertOutput(byte[] destination, byte[] expected, int written)
	{
		await Assert.That(written).IsEqualTo(expected.Length);
		await AssertOutput(destination, expected);
	}

	public static async Task AssertOutput(byte[] destination, byte[] expected)
	{
		await Assert.That(destination.AsMemory(0, expected.Length)).IsEquivalentTo(expected, CollectionOrdering.Matching);
		await Assert.That(destination.AsMemory(expected.Length)).All(static value => value is DestinationSentinel);
	}

	public static async Task AeadTest<T>
	(
		this T crypto,
		string nonceHex, string associatedDataHex, string tagHex,
		string plainHex, string cipherHex
	) where T : IAeadCipher<T>
	{
		using (crypto)
		{
			byte[] nonce = Convert.FromHexString(nonceHex);
			byte[] associatedData = Convert.FromHexString(associatedDataHex);
			byte[] tag = Convert.FromHexString(tagHex);
			byte[] plain = Convert.FromHexString(plainHex);
			byte[] cipher = Convert.FromHexString(cipherHex);
			byte[] outPlain = new byte[plain.Length];
			byte[] outTag = new byte[tag.Length];

			await Assert.That(T.NonceSize).IsEqualTo(nonce.Length);
			await Assert.That(T.TagSize).IsEqualTo(tag.Length);

			crypto.Encrypt(nonce, plain, outPlain, outTag, associatedData);
			await Assert.That(outPlain).IsEquivalentTo(cipher, CollectionOrdering.Matching);
			await Assert.That(outTag).IsEquivalentTo(tag, CollectionOrdering.Matching);

			await Assert.That(crypto.TryDecrypt(nonce, cipher, tag, outPlain, associatedData)).IsTrue();
			await Assert.That(outPlain).IsEquivalentTo(plain, CollectionOrdering.Matching);
		}
	}

	public static async Task VerifyStreamVector(IStreamCipher crypto, byte[] source, byte[] expected)
	{
		using (crypto)
		{
			byte[] actual = new byte[source.Length];
			crypto.Xor(source, actual);
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
		}
	}

	public static async Task TestBlocks(IStreamCipher crypto, IStreamCipher bulk, int length)
	{
		byte[] data = CreateDeterministicSource(length);
		byte[] expected = new byte[length];
		byte[] cipher = new byte[length];

		for (int i = 0; i < length; ++i)
		{
			crypto.Xor(data.AsSpan().Slice(i, 1), expected.AsSpan().Slice(i, 1));
		}

		bulk.Xor(data, cipher);

		await Assert.That(cipher).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	public static async Task TestBlock16<T>(byte[] key, byte[] plain, byte[] cipher) where T : IBlockCipher<T>
	{
		using T crypto = T.Create(key);
		byte[] actual = new byte[16];
		crypto.EncryptBlock(plain, actual);
		await Assert.That(actual).IsEquivalentTo(cipher, CollectionOrdering.Matching);
		crypto.DecryptBlock(cipher, actual);
		await Assert.That(actual).IsEquivalentTo(plain, CollectionOrdering.Matching);
	}

	public static async Task TestNBlock16<T>(byte[] key) where T : IBlockCipher<T>
	{
		using T crypto = T.Create(key);

		foreach (int blocks in new[] { 0, 1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 31, 32, 33, 65 })
		{
			byte[] source = CreateDeterministicSource(blocks * 16);
			byte[] expected = new byte[source.Length];

			for (int i = 0; i < source.Length; i += 16)
			{
				crypto.EncryptBlock(source.AsSpan(i, 16), expected.AsSpan(i, 16));
			}

			byte[] actual = new byte[source.Length + 7];
			PrepareDestination(actual);
			crypto.EncryptBlocks(source, actual);
			await AssertOutput(actual, expected);
			byte[] unalignedSource = new byte[source.Length + 1];
			source.CopyTo(unalignedSource, 1);
			byte[] unalignedOutput = new byte[source.Length + 2];
			PrepareDestination(unalignedOutput);
			crypto.EncryptBlocks(unalignedSource.AsSpan(1), unalignedOutput.AsSpan(1));
			await Assert.That(unalignedOutput.AsMemory(1, source.Length)).IsEquivalentTo(expected, CollectionOrdering.Matching);
			await Assert.That(unalignedOutput[0]).IsEqualTo(DestinationSentinel);
			await Assert.That(unalignedOutput[^1]).IsEqualTo(DestinationSentinel);
			crypto.DecryptBlocks(actual.AsSpan(0, source.Length), actual);
			await AssertOutput(actual, source);
			crypto.EncryptBlocks(actual.AsSpan(0, source.Length), actual);
			await AssertOutput(actual, expected);
		}
	}
}
