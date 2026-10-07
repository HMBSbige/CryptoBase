using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Modes;

public class AesXtsTest
{
	[Test]
	[Arguments(false)]
	[Arguments(true)]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
	public async Task InvalidInputsAreRejectedBeforeWriting(bool decrypt)
	{
		byte[] iv = new byte[16];
		byte[] source = CreateDeterministicSource(16);
		byte[] destination = new byte[17];
		using XtsMode<AesCipher> crypto = XtsMode<AesCipher>.Create(CreateDeterministicSource(32));

		destination.AsSpan().Fill(DestinationSentinel);
		await Assert.That(() => Transform(crypto, decrypt, iv.AsSpan(0, 15), source, destination)).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(destination).All(static value => value is DestinationSentinel);

		await Assert.That(() => Transform(crypto, decrypt, iv, source.AsSpan(0, 15), destination)).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(destination).All(static value => value is DestinationSentinel);

		await Assert.That(() => Transform(crypto, decrypt, iv, source, destination.AsSpan(0, 15))).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(destination).All(static value => value is DestinationSentinel);
	}

	[Test]
	[Arguments(0)]
	[Arguments(31)]
	[Arguments(33)]
	public async Task InvalidCombinedKeyIsRejected(int length)
	{
		await Assert.That(() => XtsMode<AesCipher>.Create(new byte[length])).ThrowsExactly<ArgumentException>();
	}

	[Test]
	public async Task UnequalKeysAreRejected()
	{
		await Assert.That(() => XtsMode<AesCipher>.Create(new byte[16], new byte[32])).ThrowsExactly<ArgumentOutOfRangeException>();
	}

	[Test]
	[Arguments(false, 0, 1)]
	[Arguments(false, 1, 0)]
	[Arguments(true, 0, 1)]
	[Arguments(true, 1, 0)]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions are awaited before the cipher is disposed.")]
	public async Task PartialOverlapIsRejectedBeforeWriting(bool decrypt, int sourceOffset, int destinationOffset)
	{
		using XtsMode<AesCipher> cipher = XtsMode<AesCipher>.Create(CreateDeterministicSource(32));
		byte[] buffer = CreateDeterministicSource(34);
		byte[] original = buffer.ToArray();
		byte[] tweak = new byte[16];
		await Assert.That(() => Transform(cipher, decrypt, tweak, buffer.AsSpan(sourceOffset, 33), buffer.AsSpan(destinationOffset, 33))).ThrowsExactly<ArgumentException>();
		await Assert.That(buffer).IsEquivalentTo(original, CollectionOrdering.Matching);
	}

	private static void Transform(XtsMode<AesCipher> crypto, bool decrypt, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		if (decrypt)
		{
			crypto.Decrypt(iv, source, destination);
		}
		else
		{
			crypto.Encrypt(iv, source, destination);
		}
	}
}
