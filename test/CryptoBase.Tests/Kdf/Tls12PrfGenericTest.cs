using CryptoBase.Abstractions.Macs;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Kdf;
using CryptoBase.Macs.Hmac;
using CryptoBase.Platform;
using System.Security.Cryptography;
using static CryptoBase.Tests.Kdf.KdfTestUtils;
using static CryptoBase.Tests.Kdf.Tls12PrfTest;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Kdf;

[GenerateGenericTest(typeof(PlatformHmacSha256))]
[GenerateGenericTest(typeof(HmacAlgorithm<Sha256Core>))]
[GenerateGenericTest(typeof(ClobberingHmacSha256))]
public class Tls12PrfGenericTest<TMac> where TMac : class, IMacAlgorithm<TMac>
{
	private const int MacLength = 32;

	// https://mailarchive.ietf.org/arch/msg/tls/fzVCzk-z3FShgGJ6DOXqM1ydxms/ (attachment tls1.2-prf-test-vectors.txt), label "test label"
	[Test]
	[Arguments(@"9bbe436ba940f017b17652849a71db35", @"a0ba9f936cda311827a6f796ffd5198c", @"e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66")]
	public async Task Sha256Vector(string secretHex, string seedHex, string outputHex)
	{
		byte[] secret = Convert.FromHexString(secretHex);
		byte[] label = "test label"u8.ToArray();
		byte[] seed = Convert.FromHexString(seedHex);
		byte[] expected = Convert.FromHexString(outputHex);

		await VerifyDerivation(secret, label, seed, ReadOnlySpan<byte>.Empty, expected);
		await VerifyDerivation(secret, label, seed.AsSpan(0, 5), seed.AsSpan(5), expected);
	}

	// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/800-135testvectors/tls.zip
	// tls.rsp (CAVS 12.0), [TLS 1.2, SHA-256], COUNT = 0 and COUNT = 1
	[Test]
	[Arguments(@"f8938ecc9edebc5030c0c6a441e213cd24e6f770a50dda07876f8d55da062bcadb386b411fd4fe4313a604fce6c17fbc", @"36c129d01a3200894b9179faac589d9835d58775f9b5ea3587cb8fd0364cae8c", @"f6c9575ed7ddd73e1f7d16eca115415812a43c2b747daaaae043abfb50053fce", @"62e1fd91f23f558a605f28478c58cf72637b89784d959df7e946d3f07bd1b616", @"ae6c806f8ad4d80784549dff28a4b58fd837681a51d928c3e30ee5ff14f39868", @"202c88c00f84a17a20027079604787461176455539e705be730890602c289a5001e34eeb3a043e5d52a65e66125188bf", @"d06139889fffac1e3a71865f504aa5d0d2a2e89506c6f2279b670c3e1b74f531016a2530c51a3a0f7e1d6590d0f0566b2f387f8d11fd4f731cdd572d2eae927f6f2f81410b25e6960be68985add6c38445ad9f8c64bf8068bf9a6679485d966f1ad6f68b43495b10a683755ea2b858d70ccac7ec8b053c6bd41ca299d4e51928")]
	[Arguments(@"b9664b35350787f891966cc494cc29340fa6e7d2db0e85ef648b640129749988fcf7c49c17989b041745d768203a554e", @"2bde249495f104e65b3b07cc88e940cd0d31c7ab6e3990dc253ff32826eea720", @"cf08c14548ac478165b03c1c08bba0ff5959a0ded3da678f03febae4a28c05cd", @"284806ac208958e6fff30ebf99d908cb00fc5af915a19a5b34cac30340031f65", @"d2ec44801e16c23e9d4cfe4c5c238523860dcca2b3f7dea5409fb31fceefa713", @"918b60d280f8471784392edbb9dd1fef7a78f823672a78fdb62822707e717a6d1ef54ca58f0b3b84a6fa092eb27089dd", @"1910e1496131f7ef05a7a568fffe7a3d3073e4f08500c97fce69d1c42a4ccf7553e52bc1ce84b760214f2632fee46ab0c4fb2bbe1214a560c7b041cbf4be44162d559ed8e8b34ab847f66aa5e948bef5a336d9d5c1e58b9ec4484f2024c4c453d87f1e9542556fe4f4615e2bdc20f74af7cf2311bd2a02bd415868339d50414d")]
	public async Task Sha256CavpVector(string preMasterSecretHex, string clientHelloRandomHex, string serverHelloRandomHex, string clientRandomHex, string serverRandomHex, string masterSecretHex, string keyBlockHex)
	{
		byte[] preMasterSecret = Convert.FromHexString(preMasterSecretHex);
		byte[] clientHelloRandom = Convert.FromHexString(clientHelloRandomHex);
		byte[] serverHelloRandom = Convert.FromHexString(serverHelloRandomHex);
		byte[] clientRandom = Convert.FromHexString(clientRandomHex);
		byte[] serverRandom = Convert.FromHexString(serverRandomHex);
		byte[] masterSecret = Convert.FromHexString(masterSecretHex);
		byte[] keyBlock = Convert.FromHexString(keyBlockHex);

		await VerifyDerivation(preMasterSecret, "master secret"u8.ToArray(), clientHelloRandom, serverHelloRandom, masterSecret);
		await VerifyDerivation(preMasterSecret, "master secret"u8.ToArray(), Concat(clientHelloRandom, serverHelloRandom), ReadOnlySpan<byte>.Empty, masterSecret);
		await VerifyDerivation(masterSecret, "key expansion"u8.ToArray(), serverRandom, clientRandom, keyBlock);
		await VerifyDerivation(masterSecret, "key expansion"u8.ToArray(), Concat(serverRandom, clientRandom), ReadOnlySpan<byte>.Empty, keyBlock);
	}

	private static Task VerifyDerivation(byte[] secret, byte[] label, ReadOnlySpan<byte> seed1, ReadOnlySpan<byte> seed2, byte[] expected)
	{
		const int offset = 3;
		byte[] buffer = CreateGuardedBuffer(offset, expected.Length);

		if (seed2.IsEmpty)
		{
			Tls12Prf<TMac>.DeriveKey(secret, label, seed1, buffer.AsSpan(offset, expected.Length));
		}
		else
		{
			Tls12Prf<TMac>.DeriveKey(secret, label, seed1, seed2, buffer.AsSpan(offset, expected.Length));
		}

		return AssertOutput(buffer, offset, expected);
	}

	[Test]
	public async Task MatchesReferenceAndNonGenericPrf()
	{
		await Assert.That(TMac.MacLength).IsEqualTo(MacLength);

		Func<byte[], byte[], byte[]> mac = PlatformMac(HashAlgorithmName.SHA256);
		int[] secretLengths = [0, 48, 65, 300];
		(int Label, int Seed)[] inputLengths = [(13, 64), (13, 0), (0, 32), (13, 71), (13, 300)];

		foreach (int secretLength in secretLengths)
		{
			byte[] secret = CreateDeterministicSource(secretLength);

			foreach ((int labelLength, int seedLength) in inputLengths)
			{
				byte[] label = CreateData(labelLength, 3);
				byte[] seed = CreateData(seedLength, 5);
				byte[] reference = ReferencePrf(mac, secret, label, seed, 3 * MacLength + 1);

				for (int outputLength = 1; outputLength <= reference.Length; ++outputLength)
				{
					byte[] expected = reference.AsSpan(0, outputLength).ToArray();
					byte[] nonGeneric = new byte[outputLength];
					Tls12Prf.DeriveKey<Sha256Core>(secret, label, seed, nonGeneric);
					await Assert.That(nonGeneric).IsEquivalentTo(expected, CollectionOrdering.Matching);

					byte[] actual = new byte[outputLength];
					Tls12Prf<TMac>.DeriveKey(secret, label, seed, actual);
					await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);

					byte[] split = new byte[outputLength];
					Tls12Prf<TMac>.DeriveKey(secret, label, seed.AsSpan(0, seedLength / 3), seed.AsSpan(seedLength / 3), split);
					await Assert.That(split).IsEquivalentTo(expected, CollectionOrdering.Matching);
				}
			}
		}
	}

	[Test]
	public async Task SupportsMoreThan255Blocks()
	{
		const int outputLength = 256 * MacLength + 7;
		byte[] secret = CreateDeterministicSource(48);
		byte[] label = "key expansion"u8.ToArray();
		byte[] seed = CreateData(64, 5);
		byte[] expected = new byte[outputLength];
		byte[] actual = new byte[outputLength];

		Tls12Prf.DeriveKey<Sha256Core>(secret, label, seed, expected);
		Tls12Prf<TMac>.DeriveKey(secret, label, seed, actual);

		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	public async Task RejectsEmptyOutput()
	{
		byte[] secret = CreateDeterministicSource(48);
		byte[] label = "master secret"u8.ToArray();
		byte[] seed = CreateData(32, 5);

		await Assert.That(() => Tls12Prf<TMac>.DeriveKey(secret, label, seed, Array.Empty<byte>())).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("output");
		await Assert.That(() => Tls12Prf<TMac>.DeriveKey(secret, label, seed, seed, Array.Empty<byte>())).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("output");
	}

	[Test]
	[MatrixDataSource]
	public async Task SupportsInputAndOutputOverlap([Matrix(PrfInput.Secret, PrfInput.Label, PrfInput.Seed1, PrfInput.Seed2)] PrfInput input, [Matrix(70, 300)] int overlappedLength, [Matrix(20, 32, 97)] int outputLength, [Matrix(0, 10)] int inputOffset, [Matrix(0, 10)] int outputOffset)
	{
		byte[] secret = CreateDeterministicSource(input is PrfInput.Secret ? overlappedLength : 48);
		byte[] label = CreateData(input is PrfInput.Label ? overlappedLength : 13, 3);
		byte[] seed1 = CreateData(input is PrfInput.Seed1 ? overlappedLength : 32, 5);
		byte[] seed2 = CreateData(input is PrfInput.Seed2 ? overlappedLength : 32, 7);
		byte[] expected = new byte[outputLength];
		Tls12Prf.DeriveKey<Sha256Core>(secret, label, seed1, seed2, expected);

		byte[] overlapped = input switch
		{
			PrfInput.Secret => secret,
			PrfInput.Label => label,
			PrfInput.Seed1 => seed1,
			_ => seed2,
		};
		byte[] buffer = new byte[Math.Max(inputOffset + overlapped.Length, outputOffset + outputLength)];
		overlapped.CopyTo(buffer, inputOffset);
		ReadOnlySpan<byte> overlappedInput = buffer.AsSpan(inputOffset, overlapped.Length);
		Span<byte> output = buffer.AsSpan(outputOffset, outputLength);

		Tls12Prf<TMac>.DeriveKey(input is PrfInput.Secret ? overlappedInput : secret, input is PrfInput.Label ? overlappedInput : label, input is PrfInput.Seed1 ? overlappedInput : seed1, input is PrfInput.Seed2 ? overlappedInput : seed2, output);

		await Assert.That(buffer.AsMemory(outputOffset, outputLength)).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(32)]
	[Arguments(48)]
	[Arguments(128)]
	public async Task SupportsSingleSeedAndOutputOverlap(int outputLength)
	{
		byte[] secret = CreateDeterministicSource(48);
		byte[] label = "key expansion"u8.ToArray();
		byte[] seed = CreateData(64, 5);
		byte[] expected = new byte[outputLength];
		Tls12Prf.DeriveKey<Sha256Core>(secret, label, seed, expected);
		byte[] buffer = new byte[Math.Max(seed.Length, outputLength)];
		seed.CopyTo(buffer, 0);

		Tls12Prf<TMac>.DeriveKey(secret, label, buffer.AsSpan(0, seed.Length), buffer.AsSpan(0, outputLength));

		await Assert.That(buffer.AsMemory(0, outputLength)).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	public async Task DoesNotModifyInputs()
	{
		byte[] secret = CreateDeterministicSource(48);
		byte[] label = "key expansion"u8.ToArray();
		byte[] seed1 = CreateData(32, 5);
		byte[] seed2 = CreateData(32, 7);
		byte[] secretCopy = (byte[])secret.Clone();
		byte[] labelCopy = (byte[])label.Clone();
		byte[] seed1Copy = (byte[])seed1.Clone();
		byte[] seed2Copy = (byte[])seed2.Clone();

		Tls12Prf<TMac>.DeriveKey(secret, label, seed1, seed2, new byte[3 * MacLength + 5]);

		await Assert.That(secret).IsEquivalentTo(secretCopy, CollectionOrdering.Matching);
		await Assert.That(label).IsEquivalentTo(labelCopy, CollectionOrdering.Matching);
		await Assert.That(seed1).IsEquivalentTo(seed1Copy, CollectionOrdering.Matching);
		await Assert.That(seed2).IsEquivalentTo(seed2Copy, CollectionOrdering.Matching);
	}
}
