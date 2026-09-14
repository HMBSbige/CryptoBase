using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Blocks.SM4;
using CryptoBase.Ciphers.Modes;
using CryptoBase.Ciphers.Streams;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Streams;

public class StreamCipherContractTest
{
	public static IEnumerable<StreamCipherCase> CipherCases()
	{
		foreach (SnuffleCase cipher in SnuffleCipherTestUtils.CipherCases())
		{
			yield return new StreamCipherCase(cipher.Name, cipher.Create);
		}

		yield return new StreamCipherCase("AesCtr", static () => CtrMode128<AesCipher>.Create(CreateDeterministicSource(32), CreateDeterministicSource(16)));
		yield return new StreamCipherCase("SM4Ctr", static () => CtrMode128<SM4Cipher>.Create(CreateDeterministicSource(32).AsSpan(0, 16), CreateDeterministicSource(16)));
	}

	[Test]
	[MethodDataSource(nameof(CipherCases))]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
	public async Task RejectedDestinationDoesNotAdvanceStateOrWrite(StreamCipherCase cipher)
	{
		using IStreamCipher subject = cipher.Create();
		using IStreamCipher oracle = cipher.Create();
		byte[] source = CreateDeterministicSource(65);
		byte[] shortDestination = new byte[source.Length - 1];
		shortDestination.AsSpan().Fill(DestinationSentinel);

		await Assert.That(() => subject.Xor(source, shortDestination)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");

		await Assert.That(shortDestination).All(static value => value is DestinationSentinel);
		byte[] actual = new byte[source.Length];
		byte[] expected = new byte[source.Length];
		subject.Xor(source, actual);
		oracle.Xor(source, expected);
		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[MethodDataSource(nameof(CipherCases))]
	public async Task ExactInPlaceOperationMatchesSeparateDestination(StreamCipherCase cipher)
	{
		using IStreamCipher inPlace = cipher.Create();
		using IStreamCipher separate = cipher.Create();
		byte[] source = CreateDeterministicSource(129);
		byte[] inPlaceBuffer = (byte[])source.Clone();
		byte[] expected = new byte[source.Length];

		inPlace.Xor(inPlaceBuffer, inPlaceBuffer);
		separate.Xor(source, expected);

		await Assert.That(inPlaceBuffer).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	public async Task SnuffleConstructorsRejectInvalidKeyAndNonceLengths()
	{
		await Assert.That(static () => new ChaCha20Cipher(new byte[31], new byte[12]).Dispose()).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(static () => new ChaCha20Cipher(new byte[32], new byte[11]).Dispose()).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(static () => new ChaCha20OriginalCipher(new byte[24], new byte[8]).Dispose()).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(static () => new ChaCha20OriginalCipher(new byte[32], new byte[7]).Dispose()).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(static () => new XChaCha20Cipher(new byte[31], new byte[24]).Dispose()).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(static () => new XChaCha20Cipher(new byte[32], new byte[23]).Dispose()).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(static () => new Salsa20Cipher(new byte[24], new byte[8]).Dispose()).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(static () => new Salsa20Cipher(new byte[32], new byte[7]).Dispose()).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(static () => new XSalsa20Cipher(new byte[31], new byte[24]).Dispose()).ThrowsExactly<ArgumentOutOfRangeException>();
		await Assert.That(static () => new XSalsa20Cipher(new byte[32], new byte[23]).Dispose()).ThrowsExactly<ArgumentOutOfRangeException>();
	}
}
