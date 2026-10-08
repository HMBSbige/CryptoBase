using CryptoBase.Hashes.Blake2b;
using CryptoBase.Macs.Hmac;
using CryptoBase.Tests.Macs;
using static CryptoBase.Tests.Hashes.HashAlgorithmTestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Hashes.Blake2b;

public class Blake2b512Test
{
	public static IEnumerable<(int Length, string ExpectedHex)> BoundaryVectors =>
	[
		(0, @"786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"),
		(1, @"c7e880e74b60b155e89b16a15aa0d82cbe017524c2931b9cbba0628e903360172ad6a54721a5077eaa308d59de1a6bd961ef0fb8d7d791ca79dabe092fbee285"),
		(63, @"b572a29a85fc9d0f0bed8fe5957a2db301140f0fc23865c3839af0ad605253a9f48781444fe04f5ef92029249ab4bc86dbcc380b8ae074cfd62aac01d9bb8245"),
		(64, @"97333e29b7588b3c4216576ae39ebe2b6b94a0686724db6e61a7b9adbb84accee4b51484405593322851f813ecda56e73db32a78c993197b9e1ac9f5067ad22d"),
		(65, @"6655cfb09226943d645ea74f340ff00b7f4cb3d614a4e75475f470b2ff11a5f944812174d1c4079ab4682c83727f89d82b690c4eebae80874a9011fafef81e35"),
		(127, @"fecfad9f28f07ee0fed84b6ac57ee441acc00de5c032aeade97cb55499179164559a84abfc170ac39aedf7547468aeaa5b9b09876166fd328665b5d32476e7f9"),
		(128, @"4459eba60d475d63cf105e196742495d7e08e58bcb48c6496f99d1fc2333367629eb48158ee5a273559d4942aa172beb9ac07330861e819acc26100b8712f574"),
		(129, @"f5632733550ce9a6f44c545ea43badb91f3b73ebb601b7562779d84b3e45be83c5a0751c6376a5fde1033464ddd92521d7402f548ad45503cf312d87fa473e9d"),
		(255, @"55625dcd6a56d0aa96fb7c9c0769da4565d69b5cef123168a7107fe042f12f907ba6315cd7b1ba39f2cfa316dd2db9143bdc24232f86a1ec627b5d00c70079f5"),
		(256, @"2788dc1d1508966c6c38cdab46e7c9121f90ec049e8fbf7bcb4afb2aefb888fef99b9cb521f9cc2fa926520773ae6e3a2c0d978a6625705f9b88655269dd4cb3"),
		(257, @"0dabd42cdbe060262e56cfe1e08cc9b0884271bcb807401c3af5753796e35ae27a19806df3250e593aeb2059f6ac55a85d4e81362653116b8b174342e5794e02"),
		(383, @"a368bccc80a3a9232277e5163dd12acacafd7acb9d671cea30d8c970afa1efd3ec6d61009cf71c8a8d85bb714cf85913d5667d08cb953e388e388f6c3919b73f"),
		(384, @"ae0c5f1eca6fae05411fd646ba6520851116aea0fd6bce62215712eb7fe962bf58241fccbc552f412fe4dc1d3813d4271cde652df7f3c961bfbff5124362dfe5"),
		(385, @"22451b64169433b74617dba0502b7d1cd5a6934cb4447e8f6d24ac302af1cc39895e7708ba93129c7a1445c3c3bcf537ae32adf7ac59490e3dcc4af9b0402bbd"),
		(511, @"90d2aa836ec4555b6dfec9c9b507552c0ce5c88f90ffbf19590de867224e72cd0811d167fdd92470226c8d8bc04d637838e06f7355532a6b2abe68bf339111cd"),
		(512, @"2a0a6cec667988548ae60d852d40b267836120be3594277293ffe276055e61d1d407e19beef380f0036cda603c7070d80bb0d8b649380dff313ca37bbfb2d971"),
		(513, @"00dc0da2db78e418c5b631bb3b35a53acf72edce25344e210a533cfe08ffd7bf59fa9e0f79bbb88bf11ac0ac40df6ffed8f08ab9151770ba14785219ff443f00"),
		(1023, @"166cc74b6d51d2bbe2f648757b7183fe50c9dc1172bdd4a345452b7c7affe1c8f1fa70fbdfbc15255cd0c05f25fd09c28f344b5afc1d2c1965dd37d4822af92a"),
		(1024, @"ece56868667fa739f7f27edaa00928d8f23a94406725f934779cc88df105622ce1de89cdf786f8fad83b7fa04722e911feb4b6db608e4a7f20c2b62ab1bf6098"),
		(1025, @"2831fdb8684831da108ac2fe4efc2299697d24d640efe063509afb65c5e1886acea14847578977a960af5b26aae24523e6d6f699419b211698fdbade3910e2fe"),
		(1153, @"9d9efaf26b5cf27466cec9949b0a8607e73183bf4d395dbf5a6daf75b4fdfb0e145efdbe0d1d65a4bb96c15bd6dc712a7e75958e687e9ea94ba43693de58215e")
	];

	[Test]
	[Arguments("", "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce")]
	[Arguments("abc", "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")]
	[Arguments("The quick brown fox jumps over the lazy dog", "a8add4bdddfd93e4877d2746e62817b116364a1fa7bc148d95090bc7333b3673f82401cf7aa2e4cb1ecd90296e3f14cb5413f8ed77be73045b13914cdcd6a918")]
	public Task KnownVectors(string value, string expected)
	{
		return VerifyHashVector<Blake2b512HashAlgorithm>(value, expected, 64, 128);
	}

	[Test]
	[MethodDataSource(nameof(BoundaryVectors))]
	public Task BlockBoundaries(int length, string expectedHex)
	{
		return VerifyBoundary<Blake2b512HashAlgorithm>(length, expectedHex);
	}

	[Test]
	[MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(Hash128IncrementalBatchCases))]
	public Task IncrementalBlockBatches(int length, int sourceOffset, int blockSize)
	{
		return VerifyIncrementalBlockBatch<Blake2b512HashAlgorithm>(length, sourceOffset, blockSize, static source => GetKnownDigest(source, BoundaryVectors, "BLAKE2b-512"));
	}

	[Test]
	[CombinedDataSources]
	public Task InputIsUnchanged([MethodDataSource(typeof(HashAlgorithmTestUtils), nameof(InputIntegrityLengths))] int length, [Arguments(1, 7)] int offset)
	{
		return VerifyInputIsUnchanged<Blake2b512HashAlgorithm>(length, offset);
	}

	[Test]
	[Arguments(0, 0, "198cd2006f66ff83fbbd913f78aca2251caf4f19fe9475aade8cf2091b99a68466775177424f58286886cbae8229644cec747237d4b721735485e17372fdf59c")]
	[Arguments(32, 3, "cee732e14baa95b860d1af4cd71cc6e2a6544d22474cd9cbcc41bd2584347e0d2303dd3a990401b6a4f481fc311d272b071bd24019a6d9ba50097c3a13f162e7")]
	[Arguments(128, 129, "c919501dc85f2c5fc1b3032e5b983a87a8ac17b9dd648780a4813d6d366ed55b1f2768612ae7b727ad3b9487c794faa497594d1e3483d5f180e9ed60e9547062")]
	[Arguments(129, 200, "c5c38636b75ff6142917257a19c267967727eef865a65384e7761ef315423f1ca70f7e634b7e711aadc1a41c2064d8d3a6842a256ad57c32a9d995aa7b80ee28")]
	public Task HmacKnownVectors(int keyLength, int sourceLength, string expectedHex)
	{
		byte[] key = CreateDeterministicSource(keyLength + 1).AsSpan(1).ToArray();
		return MacAlgorithmTestUtils.VerifyVector<HmacAlgorithm<Blake2b512HashAlgorithm>>(key, CreateDeterministicSource(sourceLength), Convert.FromHexString(expectedHex));
	}
}
