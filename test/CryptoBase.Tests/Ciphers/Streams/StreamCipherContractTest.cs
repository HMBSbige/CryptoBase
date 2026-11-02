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
		PrepareDestination(shortDestination);

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
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "The cipher is used after disposal on purpose.")]
	public async Task DisposalIsIdempotentAndEndsXor(StreamCipherCase cipher)
	{
		IStreamCipher subject = cipher.Create();
		subject.Dispose();
		subject.Dispose();
		byte[] source = CreateDeterministicSource(65);
		byte[] output = new byte[source.Length];
		PrepareDestination(output);

		await Assert.That(() => subject.Xor(source, output)).ThrowsExactly<ObjectDisposedException>();
		await Assert.That(output).All(static value => value is DestinationSentinel);
	}

	[Test]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "The ciphers are used after disposal on purpose.")]
	public async Task DisposalEndsCounterChanges()
	{
		ChaCha20Cipher chaCha20 = new(CreateDeterministicSource(ChaCha20Cipher.KeySize), CreateDeterministicSource(ChaCha20Cipher.IVSize));
		ChaCha20OriginalCipher chaCha20Original = new(CreateDeterministicSource(32), CreateDeterministicSource(ChaCha20OriginalCipher.IVSize));
		XChaCha20Cipher xChaCha20 = new(CreateDeterministicSource(XChaCha20Cipher.KeySize), CreateDeterministicSource(XChaCha20Cipher.IVSize));
		Salsa20Cipher salsa20 = new(CreateDeterministicSource(32), CreateDeterministicSource(Salsa20Cipher.IVSize));
		XSalsa20Cipher xSalsa20 = new(CreateDeterministicSource(XSalsa20Cipher.KeySize), CreateDeterministicSource(XSalsa20Cipher.IVSize));
		CtrMode128<AesCipher> ctr = CtrMode128<AesCipher>.Create(CreateDeterministicSource(16), new byte[16]);
		chaCha20.Dispose();
		chaCha20Original.Dispose();
		xChaCha20.Dispose();
		salsa20.Dispose();
		xSalsa20.Dispose();
		ctr.Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(() => chaCha20.SetCounter(1)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => chaCha20Original.SetCounter(1)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => xChaCha20.SetCounter(1)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => salsa20.SetCounter(1)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => xSalsa20.SetCounter(1)).ThrowsExactly<ObjectDisposedException>();
			await Assert.That(() => ctr.Reset(new byte[16])).ThrowsExactly<ObjectDisposedException>();
		}
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
