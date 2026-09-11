using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.Abstractions.Vectors;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;

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
		await Assert.That(destination.AsMemory(0, expected.Length)).IsEquivalentTo(expected, CollectionOrdering.Matching);
		await Assert.That(destination.AsMemory(expected.Length)).All(static value => value is DestinationSentinel);
	}

	public static async Task AeadTest(this IAeadCrypto crypto, string expectedName,
		string nonceHex, string associatedDataHex, string tagHex,
		string plainHex, string cipherHex)
	{
		using (crypto)
		{
			await Assert.That(crypto.Name).IsEqualTo(expectedName);

			byte[] nonce = Convert.FromHexString(nonceHex);
			byte[] associatedData = Convert.FromHexString(associatedDataHex);
			byte[] tag = Convert.FromHexString(tagHex);
			byte[] plain = Convert.FromHexString(plainHex);
			byte[] cipher = Convert.FromHexString(cipherHex);
			byte[] outPlain = new byte[plain.Length];
			byte[] outTag = new byte[tag.Length];

			await Assert.That(crypto.NonceSizeInBytes).IsEqualTo(nonce.Length);
			await Assert.That(crypto.TagSizeInBytes).IsEqualTo(tag.Length);
			await Assert.That(crypto.GetCiphertextSizeInBytes(plain.Length)).IsEqualTo(cipher.Length);
			await Assert.That(crypto.GetPlaintextSizeInBytes(cipher.Length)).IsEqualTo(plain.Length);

			crypto.Encrypt(nonce, plain, outPlain, outTag, associatedData);
			await Assert.That(cipher).IsEquivalentTo(outPlain, CollectionOrdering.Matching);
			await Assert.That(tag).IsEquivalentTo(outTag, CollectionOrdering.Matching);

			crypto.Decrypt(nonce, cipher, tag, outPlain, associatedData);
			await Assert.That(plain).IsEquivalentTo(outPlain, CollectionOrdering.Matching);
		}
	}

	public static async Task VerifyStreamVector(IStreamCrypto crypto, string expectedName, byte[] source, byte[] expected)
	{
		using (crypto)
		{
			byte[] actual = new byte[source.Length];
			await Assert.That(crypto.Name).IsEqualTo(expectedName);
			crypto.Update(source, actual);
			await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
		}
	}

	public static async Task TestBlocks(IStreamCrypto crypto, int length)
	{
		byte[] data = CreateDeterministicSource(length);
		byte[] expected = new byte[length];
		byte[] cipher = new byte[length];

		for (int i = 0; i < length; ++i)
		{
			crypto.Update(data.AsSpan().Slice(i, 1), expected.AsSpan().Slice(i, 1));
		}

		crypto.Reset();
		crypto.Update(data, cipher);

		await Assert.That(expected).IsEquivalentTo(cipher, CollectionOrdering.Matching);
	}

	public static async Task TestBlock16<T>(byte[] key, byte[] plain, byte[] cipher) where T : IBlock16Cipher<T>
	{
		await Assert.That(T.IsSupported).IsTrue();
		using T crypto = T.Create(key);

		await Assert.That(crypto.Encrypt(plain.AsVectorBuffer16())).IsEqualTo(cipher.AsSpan().AsVectorBuffer16());

		await Assert.That(crypto.Decrypt(cipher.AsVectorBuffer16())).IsEqualTo(plain.AsSpan().AsVectorBuffer16());
	}

	[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
	public static async Task TestNBlock16<T>(byte[] key) where T : IBlock16Cipher<T>
	{
		await Assert.That(T.IsSupported).IsTrue();
		using T crypto = T.Create(key);

		byte[] source = CreateDeterministicSource(32 * 16);
		byte[] expectedCipher = new byte[source.Length];

		for (int i = 0; i < source.Length / 16; ++i)
		{
			VectorBuffer16 encrypted = crypto.Encrypt(source.AsSpan().Slice(i * 16).AsVectorBuffer16());
			MemoryMarshal.Write(expectedCipher.AsSpan().Slice(i * 16), in encrypted);
		}

		await Assert.That(crypto.Encrypt(source.AsSpan(0, 32).AsVectorBuffer32())).IsEqualTo(expectedCipher.AsSpan(0, 32).AsVectorBuffer32());
		await Assert.That(crypto.Decrypt(expectedCipher.AsSpan(0, 32).AsVectorBuffer32())).IsEqualTo(source.AsSpan(0, 32).AsVectorBuffer32());
		await Assert.That(crypto.Encrypt(source.AsSpan(0, 64).AsVectorBuffer64())).IsEqualTo(expectedCipher.AsSpan(0, 64).AsVectorBuffer64());
		await Assert.That(crypto.Decrypt(expectedCipher.AsSpan(0, 64).AsVectorBuffer64())).IsEqualTo(source.AsSpan(0, 64).AsVectorBuffer64());
		await Assert.That(crypto.Encrypt(source.AsSpan(0, 128).AsVectorBuffer128())).IsEqualTo(expectedCipher.AsSpan(0, 128).AsVectorBuffer128());
		await Assert.That(crypto.Decrypt(expectedCipher.AsSpan(0, 128).AsVectorBuffer128())).IsEqualTo(source.AsSpan(0, 128).AsVectorBuffer128());

		if (T.HardwareAcceleration.HasFlag(BlockCipherHardwareAcceleration.Block8V256))
		{
			await Assert.That(crypto.EncryptV256(source.AsSpan(0, 128).AsVectorBuffer128())).IsEqualTo(expectedCipher.AsSpan(0, 128).AsVectorBuffer128());
			await Assert.That(crypto.DecryptV256(expectedCipher.AsSpan(0, 128).AsVectorBuffer128())).IsEqualTo(source.AsSpan(0, 128).AsVectorBuffer128());
		}
		else
		{
			await Assert.That(() => crypto.EncryptV256(default(VectorBuffer128))).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => crypto.DecryptV256(default(VectorBuffer128))).ThrowsExactly<NotSupportedException>();
		}

		if (T.HardwareAcceleration.HasFlag(BlockCipherHardwareAcceleration.Block16V256))
		{
			await Assert.That(crypto.EncryptV256(source.AsSpan(0, 256).AsVectorBuffer256())).IsEqualTo(expectedCipher.AsSpan(0, 256).AsVectorBuffer256());
			await Assert.That(crypto.DecryptV256(expectedCipher.AsSpan(0, 256).AsVectorBuffer256())).IsEqualTo(source.AsSpan(0, 256).AsVectorBuffer256());
		}
		else
		{
			await Assert.That(() => crypto.EncryptV256(default(VectorBuffer256))).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => crypto.DecryptV256(default(VectorBuffer256))).ThrowsExactly<NotSupportedException>();
		}

		if (T.HardwareAcceleration.HasFlag(BlockCipherHardwareAcceleration.Block16V512))
		{
			await Assert.That(crypto.EncryptV512(source.AsSpan(0, 256).AsVectorBuffer256())).IsEqualTo(expectedCipher.AsSpan(0, 256).AsVectorBuffer256());
			await Assert.That(crypto.DecryptV512(expectedCipher.AsSpan(0, 256).AsVectorBuffer256())).IsEqualTo(source.AsSpan(0, 256).AsVectorBuffer256());
		}
		else
		{
			await Assert.That(() => crypto.EncryptV512(default(VectorBuffer256))).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => crypto.DecryptV512(default(VectorBuffer256))).ThrowsExactly<NotSupportedException>();
		}

		if (T.HardwareAcceleration.HasFlag(BlockCipherHardwareAcceleration.Block32V512))
		{
			await Assert.That(crypto.EncryptV512(source.AsSpan().AsVectorBuffer512())).IsEqualTo(expectedCipher.AsSpan().AsVectorBuffer512());
			await Assert.That(crypto.DecryptV512(expectedCipher.AsSpan().AsVectorBuffer512())).IsEqualTo(source.AsSpan().AsVectorBuffer512());
		}
		else
		{
			await Assert.That(() => crypto.EncryptV512(default(VectorBuffer512))).ThrowsExactly<NotSupportedException>();
			await Assert.That(() => crypto.DecryptV512(default(VectorBuffer512))).ThrowsExactly<NotSupportedException>();
		}
	}
}
