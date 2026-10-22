using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes.Blake2b;
using CryptoBase.Hashes.Sha1;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Hashes.SM3;
using CryptoBase.Kdf;
using CryptoBase.Macs.Hmac;
using System.Security.Cryptography;
using static CryptoBase.Tests.Kdf.KdfTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Kdf;

public class Tls12PrfTest
{
	public enum PrfInput
	{
		Secret,
		Label,
		Seed1,
		Seed2,
	}

	private const string TestLabelHex = @"74657374206c6162656c";

	// https://mailarchive.ietf.org/arch/msg/tls/fzVCzk-z3FShgGJ6DOXqM1ydxms/ (attachment tls1.2-prf-test-vectors.txt), label "test label"
	[Test]
	[Arguments(@"e18828740352b530d69b34c6597dea2e", @"f5a3fe6d34e2e28560fdcaf6823f9091", @"224d8af3c0453393a9779789d21cf7da5ee62ae6b617873d489428efc8dd58d1566e7029e2ca3a5ecd355dc64d4d927e2fbd78c4233e8604b14749a77a92a70fddf614bc0df623d798604e4ca5512794d802a258e82f86cf")]
	public Task Sha224Vector(string secretHex, string seedHex, string outputHex)
	{
		return VerifyVector<Sha224HashAlgorithm>(secretHex, TestLabelHex, seedHex, outputHex);
	}

	// https://mailarchive.ietf.org/arch/msg/tls/fzVCzk-z3FShgGJ6DOXqM1ydxms/ (attachment tls1.2-prf-test-vectors.txt), label "test label"
	[Test]
	[Arguments(@"9bbe436ba940f017b17652849a71db35", @"a0ba9f936cda311827a6f796ffd5198c", @"e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66")]
	public Task Sha256Vector(string secretHex, string seedHex, string outputHex)
	{
		return VerifyVector<Sha256HashAlgorithm>(secretHex, TestLabelHex, seedHex, outputHex);
	}

	// https://mailarchive.ietf.org/arch/msg/tls/fzVCzk-z3FShgGJ6DOXqM1ydxms/ (attachment tls1.2-prf-test-vectors.txt), label "test label"
	[Test]
	[Arguments(@"b80b733d6ceefcdc71566ea48e5567df", @"cd665cf6a8447dd6ff8b27555edb7465", @"7b0c18e9ced410ed1804f2cfa34a336a1c14dffb4900bb5fd7942107e81c83cde9ca0faa60be9fe34f82b1233c9146a0e534cb400fed2700884f9dc236f80edd8bfa961144c9e8d792eca722a7b32fc3d416d473ebc2c5fd4abfdad05d9184259b5bf8cd4d90fa0d31e2dec479e4f1a26066f2eea9a69236a3e52655c9e9aee691c8f3a26854308d5eaa3be85e0990703d73e56f")]
	public Task Sha384Vector(string secretHex, string seedHex, string outputHex)
	{
		return VerifyVector<Sha384HashAlgorithm>(secretHex, TestLabelHex, seedHex, outputHex);
	}

	// https://mailarchive.ietf.org/arch/msg/tls/fzVCzk-z3FShgGJ6DOXqM1ydxms/ (attachment tls1.2-prf-test-vectors.txt), label "test label"
	[Test]
	[Arguments(@"b0323523c1853599584d88568bbb05eb", @"d4640e12e4bcdbfb437f03e6ae418ee5", @"1261f588c798c5c201ff036e7a9cb5edcd7fe3f94c669a122a4638d7d508b283042df6789875c7147e906d868bc75c45e20eb40c1cf4a1713b27371f68432592f7dc8ea8ef223e12ea8507841311bf68653d0cfc4056d811f025c45ddfa6e6fec702f054b409d6f28dd0a3233e498da41a3e75c5630eedbe22fe254e33a1b0e9f6b9826675bec7d01a845658dc9c397545401d40b9f46c7a400ee1b8f81ca0a60d1a397a1028bff5d2ef5066126842fb8da4197632bdb54ff6633f86bbc836e640d4d898")]
	public Task Sha512Vector(string secretHex, string seedHex, string outputHex)
	{
		return VerifyVector<Sha512HashAlgorithm>(secretHex, TestLabelHex, seedHex, outputHex);
	}

	// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/800-135testvectors/tls.zip
	// tls.rsp (CAVS 12.0), [TLS 1.2, SHA-256], COUNT = 0 and COUNT = 1
	[Test]
	[Arguments(@"f8938ecc9edebc5030c0c6a441e213cd24e6f770a50dda07876f8d55da062bcadb386b411fd4fe4313a604fce6c17fbc", @"36c129d01a3200894b9179faac589d9835d58775f9b5ea3587cb8fd0364cae8c", @"f6c9575ed7ddd73e1f7d16eca115415812a43c2b747daaaae043abfb50053fce", @"62e1fd91f23f558a605f28478c58cf72637b89784d959df7e946d3f07bd1b616", @"ae6c806f8ad4d80784549dff28a4b58fd837681a51d928c3e30ee5ff14f39868", @"202c88c00f84a17a20027079604787461176455539e705be730890602c289a5001e34eeb3a043e5d52a65e66125188bf", @"d06139889fffac1e3a71865f504aa5d0d2a2e89506c6f2279b670c3e1b74f531016a2530c51a3a0f7e1d6590d0f0566b2f387f8d11fd4f731cdd572d2eae927f6f2f81410b25e6960be68985add6c38445ad9f8c64bf8068bf9a6679485d966f1ad6f68b43495b10a683755ea2b858d70ccac7ec8b053c6bd41ca299d4e51928")]
	[Arguments(@"b9664b35350787f891966cc494cc29340fa6e7d2db0e85ef648b640129749988fcf7c49c17989b041745d768203a554e", @"2bde249495f104e65b3b07cc88e940cd0d31c7ab6e3990dc253ff32826eea720", @"cf08c14548ac478165b03c1c08bba0ff5959a0ded3da678f03febae4a28c05cd", @"284806ac208958e6fff30ebf99d908cb00fc5af915a19a5b34cac30340031f65", @"d2ec44801e16c23e9d4cfe4c5c238523860dcca2b3f7dea5409fb31fceefa713", @"918b60d280f8471784392edbb9dd1fef7a78f823672a78fdb62822707e717a6d1ef54ca58f0b3b84a6fa092eb27089dd", @"1910e1496131f7ef05a7a568fffe7a3d3073e4f08500c97fce69d1c42a4ccf7553e52bc1ce84b760214f2632fee46ab0c4fb2bbe1214a560c7b041cbf4be44162d559ed8e8b34ab847f66aa5e948bef5a336d9d5c1e58b9ec4484f2024c4c453d87f1e9542556fe4f4615e2bdc20f74af7cf2311bd2a02bd415868339d50414d")]
	public Task Sha256CavpVector(string preMasterSecretHex, string clientHelloRandomHex, string serverHelloRandomHex, string clientRandomHex, string serverRandomHex, string masterSecretHex, string keyBlockHex)
	{
		return VerifyCavpVector<Sha256HashAlgorithm>(preMasterSecretHex, clientHelloRandomHex, serverHelloRandomHex, clientRandomHex, serverRandomHex, masterSecretHex, keyBlockHex);
	}

	// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/800-135testvectors/tls.zip
	// tls.rsp (CAVS 12.0), [TLS 1.2, SHA-384], COUNT = 0 and COUNT = 1
	[Test]
	[Arguments(@"a5e2642633f5b8c81ad3fe0c2fe3a8e5ef806b06121dd10df4bb0fe857bfdcf522558e05d2682c9a80c741a3aab1716f", @"abe4bf5527429ac8eb13574d2709e8012bd1a113c6d3b1d3aa2c3840518778ac", @"cb6e0b3eb02976b6466dfa9651c2919414f1648fd3a7838d02153e5bd39535b6", @"954b5fe1849c2ede177438261f099a2fcd884d001b9fe1de754364b1f6a6dd8e", @"1b1c8568344a65c30828e7483c0e353e2c68641c9551efae6927d9cd627a107c", @"b4d49bfa87747fe815457bc3da15073d6ac73389e703079a3503c09e14bd559a5b3c7c601c7365f6ea8c68d3d9596827", @"10fd89ef689c7ef033387b8a8f3e5e8e7c11f680f6bdd71fbac3246a73e98d45d03185dde686e6b2369e4503e9dc5a6d2cee3e2bf2fa3f41d3de57dff3e197c8a9d5f74cc2d277119d894f8584b07a0a5822f0bd68b3433ec6adaf5c9406c5f3ddbb71bbe17ce98f3d4d5893d3179ef369f57aad908e2bf710639100c3ce7e0c")]
	[Arguments(@"232a3e2a13c1d85a2fb290a63f701f5d3eaa592fa9828ee355c67e7d1aeff2939efe734cb9a860215d6d1733b7b6574f", @"a1c148c1b0ca25075dc7fbcb6521749c4f5ac9bf1b27e5cf0fb4530d29e2c80c", @"0ee8ec33cd65274b0dc34919d944ee2c61343f64ed44189e67e2f4b760c70c79", @"dce4c7973f3b0468d944de1870025bcc130e7832fd3fbfcd40ad287b13ee28f9", @"c68423e2743b91bf9e2e1078bab5c5c884bd70983e0272343279e41738e943b5", @"2a1d6063b37a458b07746a7b04ed54c9ddeef5f2e488050dfb4b0f38cc5b178e3c20e6a72307efc859bd2e1c24f790c7", @"de9f2ce42403605743e84e71b2fba535bbb2020e5899d98773c140c27abbfef4b4754ff01ea10e38604ec621f48a4af14715ee81b0ba10bdbebb5104bbc2411004a2962b0e7f5c2ebb27590678510c06cf880f9f529b164e75be0b7481881089944744bc33a0b8fd35d7f7a4f1dcc1bea500919e42aabb7f84d821fb1f018a4b")]
	public Task Sha384CavpVector(string preMasterSecretHex, string clientHelloRandomHex, string serverHelloRandomHex, string clientRandomHex, string serverRandomHex, string masterSecretHex, string keyBlockHex)
	{
		return VerifyCavpVector<Sha384HashAlgorithm>(preMasterSecretHex, clientHelloRandomHex, serverHelloRandomHex, clientRandomHex, serverRandomHex, masterSecretHex, keyBlockHex);
	}

	// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/components/800-135testvectors/tls.zip
	// tls.rsp (CAVS 12.0), [TLS 1.2, SHA-512], COUNT = 0 and COUNT = 1
	[Test]
	[Arguments(@"dfef39af25c12663a91ee5d27042b9644a16ef55b81055d1bd7dcb0b8f06eb001708cdefcf82591defca1a6f1ac693ab", @"78bc5298dfe9cf8ed336c2e2f0f6b46e2456f39f35f1143cd21eaa16277025b2", @"e2339a6c681eb30808883971b1ce5b9b1ece0f3d011a96a7fff1f5f9d80ffd4b", @"b5c41ac5ebd55d136d916547fee741bc1b509f766d50b29d7378b0cebace3c8a", @"11cfbd3b45e5e917c4edbabc27b9feac833bbbacabd079465b2759fab3063330", @"a70c5fe8d34b645a20ce98969bd30858e729c77c8a5f05d3e289219d6b5752b75b75e1ca00d3329658d7f188ed1ab7e0", @"a56650076e6bdaad7e1ea42d68a0f5ffead9b6b5232ba538767e4cc6a3ae9abcae897b068645496cd620f865ce0879081a98901fb98b112ce1f00165e7d6b3288eb4d4ed9811fdbbc24e290b8e448c71da72498449ea67cfdafd66adc31a89d83cc44cf01c749fb531494ff8cb9a677762a7220e32b7f251fde09841bf97110e")]
	[Arguments(@"c0e2f0d9897fff0cfe6adb9916f5bf9aa2977977decff80c14f284e1d0391d0cdc320681177aeaca9f99ac398738632e", @"c1ae884cad43fed3e2e98beb225ffbcd93c5b3ffb634f2b658a0c39b97eed8fb", @"02bfb194b3443d2fdf4466c88a0a05c459995d360476ff76df9a088832c8ac59", @"00ac1cf7a2a6376548eba6b6f69ba9e10ab93cedca87521df83e84269628e45f", @"8e111a579904a5c79e6db0832ccb8190ee88db5fd722d8b3f96379286a19f94a", @"74348710df03212b648663bd0a2b9940190e59bdb592876c747656b26f36ce0843505b999138459cf921503ab1c2bffb", @"edeed5638bda76490ff7a3d39f8bb8bc25c9811dd8b2bcd67ddd9c588bd7f05fb8c3328bc6a3252d5a4fc6b07444f5bbb39f67a6e193adc45e282e2e40d5ffe77342101f7e414b28babb94e727cbafa0bf2fc1895ca1c3045a6b75e4d0612345988b54821072432a5b835699bba58bf7cbeb1496461fd99bd76bc82e738794b2")]
	public Task Sha512CavpVector(string preMasterSecretHex, string clientHelloRandomHex, string serverHelloRandomHex, string clientRandomHex, string serverRandomHex, string masterSecretHex, string keyBlockHex)
	{
		return VerifyCavpVector<Sha512HashAlgorithm>(preMasterSecretHex, clientHelloRandomHex, serverHelloRandomHex, clientRandomHex, serverRandomHex, masterSecretHex, keyBlockHex);
	}

	private static async Task VerifyVector<THash>(string secretHex, string labelHex, string seedHex, string outputHex) where THash : unmanaged, IHmacHashCore<THash>
	{
		byte[] secret = Convert.FromHexString(secretHex);
		byte[] label = Convert.FromHexString(labelHex);
		byte[] seed = Convert.FromHexString(seedHex);
		byte[] expected = Convert.FromHexString(outputHex);

		await VerifyDerivation<THash>(secret, label, seed, ReadOnlySpan<byte>.Empty, expected);
		await VerifyDerivation<THash>(secret, label, seed.AsSpan(0, 5), seed.AsSpan(5), expected);
	}

	private static async Task VerifyCavpVector<THash>(string preMasterSecretHex, string clientHelloRandomHex, string serverHelloRandomHex, string clientRandomHex, string serverRandomHex, string masterSecretHex, string keyBlockHex) where THash : unmanaged, IHmacHashCore<THash>
	{
		byte[] preMasterSecret = Convert.FromHexString(preMasterSecretHex);
		byte[] clientHelloRandom = Convert.FromHexString(clientHelloRandomHex);
		byte[] serverHelloRandom = Convert.FromHexString(serverHelloRandomHex);
		byte[] clientRandom = Convert.FromHexString(clientRandomHex);
		byte[] serverRandom = Convert.FromHexString(serverRandomHex);
		byte[] masterSecret = Convert.FromHexString(masterSecretHex);
		byte[] keyBlock = Convert.FromHexString(keyBlockHex);

		await VerifyDerivation<THash>(preMasterSecret, "master secret"u8.ToArray(), clientHelloRandom, serverHelloRandom, masterSecret);
		await VerifyDerivation<THash>(preMasterSecret, "master secret"u8.ToArray(), Concat(clientHelloRandom, serverHelloRandom), ReadOnlySpan<byte>.Empty, masterSecret);
		await VerifyDerivation<THash>(masterSecret, "key expansion"u8.ToArray(), serverRandom, clientRandom, keyBlock);
		await VerifyDerivation<THash>(masterSecret, "key expansion"u8.ToArray(), Concat(serverRandom, clientRandom), ReadOnlySpan<byte>.Empty, keyBlock);
	}

	private static Task VerifyDerivation<THash>(byte[] secret, byte[] label, ReadOnlySpan<byte> seed1, ReadOnlySpan<byte> seed2, byte[] expected) where THash : unmanaged, IHmacHashCore<THash>
	{
		const int offset = 3;
		byte[] buffer = CreateGuardedBuffer(offset, expected.Length);

		if (seed2.IsEmpty)
		{
			Tls12Prf.DeriveKey<THash>(secret, label, seed1, buffer.AsSpan(offset, expected.Length));
		}
		else
		{
			Tls12Prf.DeriveKey<THash>(secret, label, seed1, seed2, buffer.AsSpan(offset, expected.Length));
		}

		return AssertOutput(buffer, offset, expected);
	}

	[Test]
	public async Task MatchesPlatformHmacReference()
	{
		await VerifySweep<Sha1HashAlgorithm>(PlatformMac(HashAlgorithmName.SHA1));
		await VerifySweep<Sha256HashAlgorithm>(PlatformMac(HashAlgorithmName.SHA256));
		await VerifySweep<Sha384HashAlgorithm>(PlatformMac(HashAlgorithmName.SHA384));
		await VerifySweep<Sha512HashAlgorithm>(PlatformMac(HashAlgorithmName.SHA512));
	}

	// The platform has no HMAC for these hashes.
	[Test]
	public async Task MatchesHmacAlgorithmReference()
	{
		await VerifySweep<Sha224HashAlgorithm>(HmacAlgorithmMac<Sha224HashAlgorithm>);
		await VerifySweep<SM3HashAlgorithm>(HmacAlgorithmMac<SM3HashAlgorithm>);
		await VerifySweep<Blake2b256HashAlgorithm>(HmacAlgorithmMac<Blake2b256HashAlgorithm>);
		await VerifySweep<Blake2b512HashAlgorithm>(HmacAlgorithmMac<Blake2b512HashAlgorithm>);
	}

	private static async Task VerifySweep<THash>(Func<byte[], byte[], byte[]> mac) where THash : unmanaged, IHmacHashCore<THash>
	{
		int hashLength = THash.HashLength;
		int[] secretLengths = [0, 48, THash.HmacBlockSize + 1];
		(int Label, int Seed)[] inputLengths = [(13, 64), (13, 0), (0, 32), (13, THash.HmacBlockSize + 7)];

		foreach (int secretLength in secretLengths)
		{
			byte[] secret = CreateDeterministicSource(secretLength);

			foreach ((int labelLength, int seedLength) in inputLengths)
			{
				byte[] label = CreateData(labelLength, 3);
				byte[] seed = CreateData(seedLength, 5);
				byte[] reference = ReferencePrf(mac, secret, label, seed, 3 * hashLength + 1);

				for (int outputLength = 1; outputLength <= reference.Length; ++outputLength)
				{
					byte[] expected = reference.AsSpan(0, outputLength).ToArray();
					byte[] actual = new byte[outputLength];
					Tls12Prf.DeriveKey<THash>(secret, label, seed, actual);
					await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);

					byte[] split = new byte[outputLength];
					Tls12Prf.DeriveKey<THash>(secret, label, seed.AsSpan(0, seedLength / 3), seed.AsSpan(seedLength / 3), split);
					await Assert.That(split).IsEquivalentTo(expected, CollectionOrdering.Matching);
				}
			}
		}
	}

	[Test]
	public async Task SupportsMoreThan255Blocks()
	{
		const int outputLength = 256 * 20 + 7;
		byte[] secret = CreateDeterministicSource(48);
		byte[] label = "key expansion"u8.ToArray();
		byte[] seed = CreateData(64, 5);
		byte[] expected = ReferencePrf(PlatformMac(HashAlgorithmName.SHA1), secret, label, seed, outputLength);
		byte[] actual = new byte[outputLength];

		Tls12Prf.DeriveKey<Sha1HashAlgorithm>(secret, label, seed, actual);

		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	public async Task RejectsEmptyOutput()
	{
		byte[] secret = CreateDeterministicSource(48);
		byte[] label = "master secret"u8.ToArray();
		byte[] seed = CreateData(32, 5);

		await Assert.That(() => Tls12Prf.DeriveKey<Sha256HashAlgorithm>(secret, label, seed, Array.Empty<byte>()))
			.ThrowsExactly<ArgumentOutOfRangeException>()
			.WithParameterName("output");
		await Assert.That(() => Tls12Prf.DeriveKey<Sha256HashAlgorithm>(secret, label, seed, seed, Array.Empty<byte>()))
			.ThrowsExactly<ArgumentOutOfRangeException>()
			.WithParameterName("output");
	}

	[Test]
	[MatrixDataSource]
	public async Task SupportsInputAndOutputOverlap([Matrix(PrfInput.Secret, PrfInput.Label, PrfInput.Seed1, PrfInput.Seed2)] PrfInput input, [Matrix(20, 32, 97)] int outputLength, [Matrix(0, 10)] int inputOffset, [Matrix(0, 10)] int outputOffset)
	{
		const int overlappedLength = 70;
		byte[] secret = CreateDeterministicSource(input is PrfInput.Secret ? overlappedLength : 48);
		byte[] label = CreateData(input is PrfInput.Label ? overlappedLength : 13, 3);
		byte[] seed1 = CreateData(input is PrfInput.Seed1 ? overlappedLength : 32, 5);
		byte[] seed2 = CreateData(input is PrfInput.Seed2 ? overlappedLength : 32, 7);
		byte[] expected = ReferencePrf(PlatformMac(HashAlgorithmName.SHA256), secret, label, Concat(seed1, seed2), outputLength);

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

		Tls12Prf.DeriveKey<Sha256HashAlgorithm>(input is PrfInput.Secret ? overlappedInput : secret, input is PrfInput.Label ? overlappedInput : label, input is PrfInput.Seed1 ? overlappedInput : seed1, input is PrfInput.Seed2 ? overlappedInput : seed2, output);

		await Assert.That(buffer.AsMemory(outputOffset, outputLength)).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[Arguments(48)]
	[Arguments(128)]
	public async Task SupportsSingleSeedAndOutputOverlap(int outputLength)
	{
		byte[] secret = CreateDeterministicSource(48);
		byte[] label = "key expansion"u8.ToArray();
		byte[] seed = CreateData(64, 5);
		byte[] expected = ReferencePrf(PlatformMac(HashAlgorithmName.SHA256), secret, label, seed, outputLength);
		byte[] buffer = new byte[Math.Max(seed.Length, outputLength)];
		seed.CopyTo(buffer, 0);

		Tls12Prf.DeriveKey<Sha256HashAlgorithm>(secret, label, buffer.AsSpan(0, seed.Length), buffer.AsSpan(0, outputLength));

		await Assert.That(buffer.AsMemory(0, outputLength)).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	// P_hash written directly from RFC 5246, section 5.
	internal static byte[] ReferencePrf(Func<byte[], byte[], byte[]> mac, byte[] secret, byte[] label, byte[] seed, int length)
	{
		byte[] labelAndSeed = Concat(label, seed);
		byte[] output = new byte[length];
		byte[] a = labelAndSeed;

		for (int offset = 0; offset < length;)
		{
			a = mac(secret, a);
			byte[] block = mac(secret, Concat(a, labelAndSeed));
			int count = Math.Min(block.Length, length - offset);
			block.AsSpan(0, count).CopyTo(output.AsSpan(offset));
			offset += count;
		}

		return output;
	}

	internal static Func<byte[], byte[], byte[]> PlatformMac(HashAlgorithmName name)
	{
		return (key, source) => CryptographicOperations.HmacData(name, key, source);
	}

	private static byte[] HmacAlgorithmMac<THash>(byte[] key, byte[] source) where THash : unmanaged, IHmacHashCore<THash>
	{
		byte[] mac = new byte[HmacAlgorithm<THash>.MacLength];
		HmacAlgorithm<THash>.Mac(key, source, mac);
		return mac;
	}
}
