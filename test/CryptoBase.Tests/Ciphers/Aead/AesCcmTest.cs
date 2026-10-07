using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
using CryptoBase.Ciphers.Modes.Ccm;
using CryptoBase.Tests.Ciphers.Modes;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;
using BclAes = System.Security.Cryptography.Aes;

namespace CryptoBase.Tests.Ciphers.Aead;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class AesCcmTest
{
	private const int MaxMessageLength = (1 << 24) - 1;

	public static IEnumerable<int> MessageLengths()
	{
		// Every final block length, then longer runs of full blocks.
		return [.. Enumerable.Range(0, 34), 127, 128, 129, 255, 256, 257, 4096, 4097];
	}

	public static IEnumerable<int> AssociatedDataLengths()
	{
		// The first block holds 14 bytes after a 2-byte length and 10 bytes after a 6-byte length.
		return [1, 13, 14, 15, 29, 30, 31, 0xFEFF, 0xFF00, 0xFF09, 0xFF0A, 0xFF0B, 0x10000];
	}

	[Test]
	// https://github.com/C2SP/wycheproof/blob/main/testvectors_v1/aes_ccm_test.json
	// tcId 1
	[Arguments
	(
		@"bedcfb5a011ebc84600fcb296c15af0d",
		@"438a547a94ea88dce46c6c85",
		@"",
		@"25d1a38495a7dea45bda049705627d10",
		@"",
		@""
	)]
	// tcId 13
	[Arguments
	(
		@"d97c9b043bdccfd59491a995e78f1696",
		@"ef423240358830df915506a3",
		@"3ddba7b3ab69c8b2",
		@"cff4c61882b413b686ff35b63a3a73de",
		@"f047594a5cffda64303a80b2fa6a957169",
		@"e0caf2a9d50f70ecaa43b4a287c3b34a99"
	)]
	// tcId 34
	[Arguments
	(
		@"8b48841001f1d689492a21218b32420a",
		@"bc66eade95cde95b3b4a29f0",
		@"7d107545f85b1e5ac6d6e7f147756a0b915a32bb77b06c3048b67e90927a986f0ddf2afddf18e1d6843d99c01e65ff001fb8a984e3305f5fa3cbf9e5d356d6eb2d46df4e59457b1094230100379ee74054253483510d5492e21c338a1ffb49510d969126029c23c248d35293d536e110d2c480ede9b6a8ee097edda1be6a1d139c5f7a913494c595d3d2731ea6fdddcd2e9029d075f3de1496bbf3e06ff9f4cc9d10980f56ceda4f3cf73243e5884f1bac216093a01d636ee1ce9c918680d4d84d16d6b77f5e4aedf9cafaffd4fad889e0dc9452e23644d9279dfcd5d11429da74d34589311ffdf2877ca71a1f40835ea4ed48995bd2a1e1f051ef2acb2e6907f9",
		@"ce63b7b9705e3ecf8485965a6ed5edce",
		@"455f2cbae83eddc667bc45b8429e8424",
		@"e6441de02b7bab8be1b343e18c880119"
	)]
	// tcId 43
	[Arguments
	(
		@"f01a3c3559c58e80bc832544e069ef29",
		@"cd5bc2aed48c3be836d7d786",
		@"",
		@"3c19cc17c028035ed04a7837340791c1",
		@"0de5aac3f151b526751de8f36010e4394498eba3c8bc790fd4ba96eb2da33e40ddca3cb36fec102ef37a6a5132cd389bbcabbd15e1c9d2700af35f19a01ba3b26843ab50833f252befbbb5529173d51ca364d7d09468b3b68f740a6014b5b824206a6a7118bf144a223f87d76624c138bd24a5fa996f36e316087f3b59c1c71cd74a9184a518c8d9aa8c7243102dd39a93599e7bbe7dcd354d0780253767e9602f2f0cbbab7eae8d8c12cbad163f8fc20d32559f798d2b7285dba6f66dc28d9b3f0a301aa89f5cd1b5a1734fe72c68f98c861d26e7dddaa08a227999f7c98d7315e7c2e3c3f198cdd4cfd62f62389998c7b760106d0a437f5050f74f9ce63948f5494bed71c88be443654ef9eb0c867eede225c1bda181baabd8155360ccae65e54d399a3f7d670d11b53d7bbecda15d53e129ef2be29154e3c21411e6207977e2620007cf4b987dd2c304efe55bc2ef564074cd6e176a97184bff4cad0cd0cb85195c4e8398f27ca0d4d8c4851359eebdb606a213223903513f0db8c0fcc1f3a834738f6c9dd6adb43bdcbd921e7c3cd3b252e319f9e711edf55e8d7f1a320705a3ba77bfa33463a922a9f36b483590c4939fd977ace51c506d2e269b488a7169b696d828458ecb092ae3a9adf63a3a12809da51fc7340fc57db50fa1903f1c7de9ce606f1de3f95538823c04e3bfb6549385643710a2919f2fbd54887bdfb239",
		@"2aeae651b99cb22c346e1e41daf34bd4f57d0d4a15a5657ee3b4fdff8ef100ae074b546504bfecea9233676e669d8f0d342f1df07aa4a0aab8c75cb14553949a1c71b3ccfa7847c8a1dbb9202b428f1b8e958e421a7e119f33af8e60fbe9a01d0dce264bce5ec9d45e0845d2d4283bc642590b305647c6aa9e3bba22ba8fb028fe2098613e45781ecdeba4bf9972c00642d78fc1040882459df98a31c4fec36863754a78e54f982ed52acb6aeb7333e46098a24a8a37e056790c6c5270dcd1a90191203c427d5a17882d96bd6369e5cba7da273966232e9a97c9f50505d2c8dc17474d6e7cafa6f2e8b114aaac28742094d3ab4d57e4a9a4ee475ade5b3002a982de07d0bffcd5d6e365b9acba7d573502251b4c0de971ddefc9a1e0b3e54eeafabfeb1c3be61c42c97bd9212c40f3bd45e6fd57f7fb6bde2ab37d7a51c4c4b4c3fad290d93d581792c0f3068bcfb7693f3fee7c2a19f877c9d652450ad209a3b2e22e44d22fa0fa796d056fbd982ed06e121583bcad2e3c41b0e1d078c1bf1fefcedb48286a79e4024392ecde87c15aa899f2d83302bbdfca66e77f8df362671f0edbbc410d91deefa18d4bbaaa560d7eedd8d2f2f76e8d6deacf8cbdc43f92e841d9155de3b6c4ea400a1534e21181a7e65b29536646dd606c4cd30bf320b5cb989d29b71ebe5b0207a6f243fadede3c916ecfec991e425c2945e295c4d96dbe"
	)]
	// tcId 51
	[Arguments
	(
		@"2c9b9ff47d742c4ab224e9ca1ed57c4c",
		@"917962caf3932441c259282f",
		@"72175bdfdb4a23e97fdcbd263baf4316",
		@"a4866908e664ee140c6ae2b9d2ab8416",
		@"b542c2f3f81670ddf74f15184ab7de17e057cde9eef92babdb837500774c19",
		@"320ae0c11e92d10d5bf5485c854b2d8f6318e33f16b520cffd35ada381c967"
	)]
	// tcId 91
	[Arguments
	(
		@"e258b117c2fdd75587f07b400ae4af3e673a51dcf761e4ca",
		@"5ead03aa8c720d21b77075db",
		@"27702950960b9c79",
		@"72ac478a66f5637563f1f12c1d0267ca",
		@"afe96113a684bc52a6d962cf2724f6791d",
		@"7830446f333057d996a1a79b21c68d8b43"
	)]
	// tcId 115
	[Arguments
	(
		@"ba51abc7107c904591fe600a49cf8c2c89ebb1fa22cc5993",
		@"116ca1ce3ccf9e8c43dbe96f",
		@"194daafadc8ab5ab72c7a16f3144c5ee3262411897987b2ecce2dde18318138f835de56643481338d8abebcb9e0df0f9dfcd022298a7fd0f83ab8101aa7fc28e61f04616f4e33f0e671af284bee80108cbb7b3dbd573b92738510a434bab84c35f1f59a3cd1f1ea5f2bfc25042a158c8d044963e4191f29b0bc6ac4ad2721a21c7fde265b383220f5a1401365721bd04f01f8c66ea94629f98fd3939d280e7990274090abb8536e47becc3493a279d273869c3b3191df668522cfcffb56933c80297f85e891e2008fa1c520027874b07ace0d1b62348df16bf3e621f9587aa1475c62e5e48b9b663c9679b067da6a950a4fdd9ae4b7dd9e1ec3e9be973bfabf7f4022b08ccc652241b9564c3618abca0c5a0d6658d330009635dcc9f5d0fa97cadcc583f7a26319832771c4cdf8b03dc609a6794539ce4c8b93ce9b92cba645cbb7491be9dd18d936c8c31596ab4849d7974287a7d97b1ebdb3fbf8d4568c2ac346fa44ac6e2cb48159ff3cebc41cc8f96aadf6f7a25aa7b6db7284025e05fde062c48dca3684812294b6e214340ec67d4dcc9ed2769b0e4155be3bd75e3d91fd89ec2c696668e9856ee799fd76a3758f07f7995a8f80d280b479d35f69e9237dc716754650536afedcddb7cc85b938e931d315f0b1e0caabfe3e71521444b7f0405ce57b7223e48d4d102a469d272d22f35dddf23730baa6111371a1003109515",
		@"c19bada8558df8f633703c6f5f05459b",
		@"f2ab9bcd8672b1fb17a75bcdb49126c4",
		@"eeaee8d5181053596d4ff057b9f48298"
	)]
	// tcId 118
	[Arguments
	(
		@"e602188abf6a91f3e258838cea6befeffcf6257a509c3e95",
		@"9e35d3ef1897c5fe3f647204",
		@"",
		@"5c13c4a8b48d26f26521b3e918065845",
		@"3b9a6edc44848c072341fd4af51ec116ac328f69cc5a3354e49299fb2e5d22fa0084e30b36ecaf54309397b2b498d686087f3457698c3639e73ca18c78c3e021d673986cfc2ceb4d07e66971e976f58f0336f82c7fc0d52d66610f26ca3bfe53c0b01cf7c207306db904c1ad300ab95c56fde820a8edd256f2b9906b312bf7af5ef4a806f618ddfcb67179b03fff80a245c38d8f4cff2875b71a0bf69129caf97121462e0501ec6574ede94706f4a04d2fb301d415c22ea12157d2e919bc7a0169a5ad5c7bb5761a8531abbe77d66a4871b3f27a7170f099044b9fdc50a8cb3b894252a501cc896ac4793bdb478bb1cb99c02341d7238dd8d593cfda02f7d520d7",
		@"da1f5ba5816b38cd389be4aa1a0d2c97d403c63a6879c1730e8e57089d19efaafee76852b5e7e8838ad57e69cc88646875df34fe46f0530434bcd80f805181b137fab4f18af5b94f509c5c45690a00592bb6d0cb0e40d2ed11606c3f6479883ae0dabe523907605cbbc8ef701abde520309cbec203ce15a51832fb2d7aecd662f6790ab152317c03f28a0e3c52668c1de6e7f9ebb35957b540dbe26234284a0bd56db0a8031fb55dc6f4df2dea46a372fa1174b066902e30b9fe691248f2c33e3d5d196d34335fe66c7b347daab698f8a49984ed0dd7f69be69adc394e72539f3b90fea64f1205b292b4b2c5b777d69fcba8cabb1417f5c393fcb3a6dde80d01a9"
	)]
	// tcId 169
	[Arguments
	(
		@"f60c6a1b625725f76c7037b48fe3577fa7f7b87b1bd5a982176d182306ffb870",
		@"f0384fb876121410633d993d",
		@"9aaf299eeea78f79",
		@"b721be96a6b95c0931fb243dd1287c70",
		@"63858ca3e2ce69887b578a3c167b421c9c",
		@"f05e290bbbc61927fa65760648dcca88b0"
	)]
	// tcId 190
	[Arguments
	(
		@"5d97d19c96153a7cfef2e5f4e27211d3bcc1826c67a6cc0bb02a46f944a85a5f",
		@"669ea62069c7199d9ca2be41",
		@"d218d976cedc3dd23ce31944405bcd0e44d5fc776838f5154c786d20fb7a39ea2e2e426fa6ce7a011ca05b5f6615e20373f7c80e98cebf8518339ba65b60532de536d3cfecf2a6b8a88a64149feba8de320a697f6a1339b0739927dd22641b8745cd04fb5fcc136dd2f3c921694005dff53ce44213fbc13f67402f882b13b28198fca970847356e2a82a2e79912ff6a1a9de8f4fed47b45b445dcd6c7400fdbc4a5da53bdfa03bad3d99b2e6038e334529b9c6f23f5135eef61db819b7ab1c7da3d1beceb4c2d212250f15fd301901db51a08d2b496e6e1f3e45af39e9556aed00b90e06535418a650bf9ab9f0e5d753f8a2e5d17c1409aba72b50fc161b2d0557",
		@"baf22d20759ec6e6f66baed50860f061",
		@"400037002b7dd892f3e582a3386e9632",
		@"49d4951657a4a362ccc71356283ccc3c"
	)]
	// tcId 199
	[Arguments
	(
		@"afd579aa1accc682aca54e142aa69df09802f020b24a42c41db58f6997edc678",
		@"9f79d1da957491069d774496",
		@"",
		@"8fe4b155059fbe8df29431d824f337e5",
		@"bafc6e865c48bd34b7f9329e35cfb286cd4dc31f8316171218bf0471dffd35a330a181697ca5178688dd87efe527924f90d1c78ba40de70952ff44c26efe2159e59358f3931573df9373a73b91ba9592e12140cc009feedd2595e5b6f066b5ef6de99d4c31552cecb0614f1dce990e46e7694382f3cf3ccfcd1ea62e563e5f0dc36cb5a84e0c0b3f1f8f3fa9100f487195ff2e3169ad08136aa8ad566548c9836aa00dbac74716c26e838c1486a0084d3dfd692585e2e5ae7c75caf0e7af60219f96116ae963b4a5899cb30a120daaca7833776692c25ad7c185e6a2d70ce03ff156cd25d76153539d6855773e21142f9ba0313562875f105a2b770a15b533fbf5110dafb69329982ab44ed1b9f321d7b79ae15a19d9f3bd4c504c24b23b812d514c19ae2a347cc18c12ce915a0bad7cc89a8720d4ba5ee0964fe05e4cc59a13f92c670b8655071e216f19ad05f4bbcca6dc7feeb188d6269c58065c98fcbbac183a9abb3811d80cb476544bd74b26991f3df987f0ed0ea6238659ac09a2250fecc0723ffc51647b74bdf454f26e11112c8bbd797f09a3be8251c6b5b319ed9537278cc1abedb32aa10840984b96e8636b289335846ae4fbd4a00f6600d98ebe25885c68d7043ce0dc5229d7e9bd51bea9b8fe0552f40688429c482629ced623f6074858147e73da3ff4ad2ae45c1a1c8a6c5b3b2c3d568a756608179f63b580fd",
		@"abc5600eece56730b6e4e738cafd0fb6be35cd23c2979dfc90ced9c49aadb00228f686ede131042f28c8705af642a12e32c8ba97fbefd281faa82bedb462a51d3cfaf500b30144c0faca4a6c769f801be4b12696fcb3f196c7eddabab944cdda8016c231a1f94512bbeea10404c3ae21b97388b259e97b49549ea908c33efcc739690a5cd9436e24b26a769ad761e736a4d4bbc30dc6bf188ebe258dad1ebddcf0af9e37affe04f960c56ae0b1fef9c5ff06d3bb53cb81923d472e1119d200f4f9471c7dcdfb0ffd44664c9007543833b7b247734232120282dfadb4448818486b810b50bce5d3a93a422790a142d40020a47f1a777ae74a6b55ce4352148975b3caa8e2256eace10889efa643a70363dccae4293dc8640725717543d8dcb2e968b2377e53a3fda4baa4aa16bb15155fb12898d0a2b8c6578123711df4856ffb42f67534e8300773340914314293c51df9e523127cce0a7b6589425aa2e3afc613b71b9c7808ed574f394597d54f6eb3d0c0d8634189d3cbc6098e3d83ccb29896ed037923a212dae3991ae9196bc0893cb706b1e6c0dc28fb5c189e433a1f7ef4e908d2f73658d19026612e964992544f9583e407ef1cc8566964699b377311c465a47033b9e15b583685f5c88faffe206064b457c70feb4da75b61a51c676166860fe28bf91d596d6eb4d30f80360f99412bfbbc057a7d5cbe16bec79cf01ea2"
	)]
	// tcId 207
	[Arguments
	(
		@"f59abcbf4218bd5c7601f080b5fbd3ae088733702c8fbef0c5296a406f563827",
		@"a5eb0e6fe669e68239ace550",
		@"d603491fbf0950d36489abb40dd8d42b",
		@"56aabbde47ab2c53db48703033f8ca68",
		@"97dcbacd70a678cfaed13c942cf920e851ec3e6fb1f6c6eb95f1c965fb1a13",
		@"c0b27edd6533cfba81323ac78d0aeb0371b1d7b89938e04c319148961513fb"
	)]
	public async Task Test(string keyHex, string nonceHex, string associatedDataHex, string tagHex, string plainHex, string cipherHex)
	{
		byte[] key = Convert.FromHexString(keyHex);
		await CcmMode128<AesCipher>.Create(key).AeadTest(nonceHex, associatedDataHex, tagHex, plainHex, cipherHex);
	}

	// NIST SP 800-38C Appendix C examples 1-3 use other nonce and tag sizes, so they validate the reference model.
	[Test]
	[Arguments(@"10111213141516", @"0001020304050607", @"20212223", @"7162015b", @"4dac255d")]
	[Arguments(@"1011121314151617", @"000102030405060708090a0b0c0d0e0f", @"202122232425262728292a2b2c2d2e2f", @"d2a1f0e051ea5f62081a7792073d593d", @"1fc64fbfaccd")]
	[Arguments(@"101112131415161718191a1b", @"000102030405060708090a0b0c0d0e0f10111213", @"202122232425262728292a2b2c2d2e2f3031323334353637", @"e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5", @"484392fbc1b09951")]
	public async Task ReferenceMatchesSp80038C(string nonceHex, string associatedDataHex, string plainHex, string cipherHex, string tagHex)
	{
		await AssertReferenceMatchesSp80038C(nonceHex, Convert.FromHexString(associatedDataHex), plainHex, cipherHex, tagHex);
	}

	// NIST SP 800-38C Appendix C example 4 uses a 6-byte associated data length encoding.
	[Test]
	public async Task ReferenceMatchesSp80038CLongAssociatedData()
	{
		byte[] associatedData = new byte[1 << 16];

		for (int i = 0; i < associatedData.Length; ++i)
		{
			associatedData[i] = (byte)i;
		}

		await AssertReferenceMatchesSp80038C(@"101112131415161718191a1b1c", associatedData, @"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f", @"69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72", @"b4ac6bec93e8598e7f0dadbcea5b");
	}

	[Test]
	[MatrixDataSource]
	public async Task MessagesMatchReference([Matrix(16, 24, 32)] int keyLength, [MatrixMethod<AesCcmTest>(nameof(MessageLengths))] int length)
	{
		byte[] key = CreateDeterministicSource(keyLength);
		byte[] nonce = CreateDeterministicSource(CcmMode128<AesCipher>.NonceSize);
		byte[] associatedData = CreateDeterministicSource(29);
		byte[] plaintext = CreateDeterministicSource(length);
		(byte[] expected, byte[] expectedTag) = EncryptReference(key, nonce, plaintext, associatedData);

		using (CcmMode128<AesCipher> cipher = CcmMode128<AesCipher>.Create(key))
		{
			await CcmTestUtils.AssertMessage(cipher, nonce, plaintext, associatedData, expected, expectedTag);
		}

		await AssertBuffered<CcmTag16>(key, nonce, plaintext, associatedData, expected, expectedTag);
	}

	[Test]
	[MatrixDataSource]
	public async Task AssociatedDataLengthEncodingMatchesReference([MatrixMethod<AesCcmTest>(nameof(AssociatedDataLengths))] int associatedDataLength)
	{
		byte[] key = CreateDeterministicSource(16);
		byte[] nonce = CreateDeterministicSource(CcmMode128<AesCipher>.NonceSize);
		byte[] associatedData = CreateDeterministicSource(associatedDataLength);
		byte[] plaintext = CreateDeterministicSource(17);
		(byte[] expected, byte[] expectedTag) = EncryptReference(key, nonce, plaintext, associatedData);
		using CcmMode128<AesCipher> cipher = CcmMode128<AesCipher>.Create(key);
		await CcmTestUtils.AssertMessage(cipher, nonce, plaintext, associatedData, expected, expectedTag);
	}

	[Test]
	[MatrixDataSource]
	public async Task MessagesMatchBcl([Matrix(16, 24, 32)] int keyLength, [Matrix(0, 1, 16, 17, 4097)] int length, [Matrix(0, 30, 0xFF0A)] int associatedDataLength)
	{
		if (!AesCcm.IsSupported)
		{
			Skip.Test("AES-CCM is not supported by the platform.");
		}

		byte[] key = CreateDeterministicSource(keyLength);
		byte[] nonce = CreateDeterministicSource(CcmMode128<AesCipher>.NonceSize);
		byte[] associatedData = CreateDeterministicSource(associatedDataLength);
		byte[] plaintext = CreateDeterministicSource(length);
		(byte[] expected, byte[] expectedTag) = EncryptBcl(key, nonce, plaintext, associatedData);
		using CcmMode128<AesCipher> cipher = CcmMode128<AesCipher>.Create(key);
		await CcmTestUtils.AssertMessage(cipher, nonce, plaintext, associatedData, expected, expectedTag);
	}

	[Test]
	public async Task MessageLengthIsLimitedByTheLengthField()
	{
		byte[] key = CreateDeterministicSource(16);
		byte[] nonce = CreateDeterministicSource(CcmMode128<AesCipher>.NonceSize);
		byte[] plaintext = CreateDeterministicSource(MaxMessageLength + 1);
		byte[] ciphertext = new byte[plaintext.Length];
		byte[] tag = new byte[CcmMode128<AesCipher>.TagSize];
		using CcmMode128<AesCipher> cipher = CcmMode128<AesCipher>.Create(key);
		PrepareDestination(ciphertext);
		PrepareDestination(tag);

		await Assert.That(() => cipher.Encrypt(nonce, plaintext, ciphertext, tag)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("source");
		await Assert.That(IsUnchanged(ciphertext)).IsTrue();
		await Assert.That(IsUnchanged(tag)).IsTrue();
		await Assert.That(() => cipher.TryDecrypt(nonce, plaintext, tag, ciphertext)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("source");
		await Assert.That(IsUnchanged(ciphertext)).IsTrue();

		cipher.Encrypt(nonce, plaintext.AsSpan(0, MaxMessageLength), ciphertext, tag);
		await Assert.That(ciphertext[MaxMessageLength]).IsEqualTo(DestinationSentinel);

		// The final partial block uses counter 2^20, which must not carry into the nonce.
		const int finalOffset = MaxMessageLength & -16;
		byte[] finalKeyStream = EncryptBlocks(key, [2, .. nonce, 0x10, 0x00, 0x00]);
		byte[] expectedFinalBlock = new byte[MaxMessageLength - finalOffset];

		for (int i = 0; i < expectedFinalBlock.Length; ++i)
		{
			expectedFinalBlock[i] = (byte)(plaintext[finalOffset + i] ^ finalKeyStream[i]);
		}

		await Assert.That(ciphertext.AsMemory(finalOffset, expectedFinalBlock.Length)).IsEquivalentTo(expectedFinalBlock, CollectionOrdering.Matching);

		if (AesCcm.IsSupported)
		{
			(byte[] expected, byte[] expectedTag) = EncryptBcl(key, nonce, plaintext.AsSpan(0, MaxMessageLength).ToArray(), []);
			await Assert.That(ciphertext.AsMemory(0, MaxMessageLength).Span.SequenceEqual(expected)).IsTrue();
			await Assert.That(tag).IsEquivalentTo(expectedTag, CollectionOrdering.Matching);
		}

		byte[] recovered = new byte[MaxMessageLength];
		await Assert.That(cipher.TryDecrypt(nonce, ciphertext.AsSpan(0, MaxMessageLength), tag, recovered)).IsTrue();
		await Assert.That(recovered.AsSpan().SequenceEqual(plaintext.AsSpan(0, MaxMessageLength))).IsTrue();
	}

	private static async Task AssertReferenceMatchesSp80038C(string nonceHex, byte[] associatedData, string plainHex, string cipherHex, string tagHex)
	{
		byte[] key = Convert.FromHexString(@"404142434445464748494a4b4c4d4e4f");
		byte[] expectedTag = Convert.FromHexString(tagHex);
		(byte[] ciphertext, byte[] tag) = EncryptReference(key, Convert.FromHexString(nonceHex), Convert.FromHexString(plainHex), associatedData, expectedTag.Length);
		await Assert.That(ciphertext).IsEquivalentTo(Convert.FromHexString(cipherHex), CollectionOrdering.Matching);
		await Assert.That(tag).IsEquivalentTo(expectedTag, CollectionOrdering.Matching);
	}

	internal static (byte[] Ciphertext, byte[] Tag) EncryptReference(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData, int tagLength = 16)
	{
		return CcmReference.Encrypt(blocks => EncryptBlocks(key, blocks), nonce, plaintext, associatedData, tagLength);
	}

	private static byte[] EncryptBlocks(byte[] key, byte[] blocks)
	{
		using BclAes aes = BclAes.Create();
		aes.Key = key;
		return aes.EncryptEcb(blocks, PaddingMode.None);
	}

	internal static (byte[] Ciphertext, byte[] Tag) EncryptBcl(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData, int tagLength = 16)
	{
		using AesCcm aes = new(key);
		byte[] ciphertext = new byte[plaintext.Length];
		byte[] tag = new byte[tagLength];
		aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);
		return (ciphertext, tag);
	}

	// Exercises the path used when AES-NI and ARM64 AES are unavailable.
	internal static async Task AssertBuffered<TTag>(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData, byte[] expected, byte[] expectedTag) where TTag : struct, ICcmTag
	{
		(byte[] ciphertext, byte[] tag, bool authenticated, byte[] recovered, bool forged, byte[] rejected) = TransformBuffered<TTag>(key, nonce, plaintext, associatedData);
		await Assert.That(ciphertext).IsEquivalentTo(expected, CollectionOrdering.Matching);
		await Assert.That(tag).IsEquivalentTo(expectedTag, CollectionOrdering.Matching);
		await Assert.That(authenticated).IsTrue();
		await Assert.That(recovered).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
		await Assert.That(forged).IsFalse();
		await Assert.That(rejected.AsSpan().ContainsAnyExcept((byte)0)).IsFalse();
	}

	private static (byte[] Ciphertext, byte[] Tag, bool Authenticated, byte[] Plaintext, bool Forged, byte[] Rejected) TransformBuffered<TTag>(byte[] key, byte[] nonce, byte[] plaintext, byte[] associatedData) where TTag : struct, ICcmTag
	{
		using AesCipher aes = AesCipher.Create(key);
		byte[] buffer = new byte[BufferedCcmBlockEncryptor<AesCipher>.BufferSize];
		BufferedCcmBlockEncryptor<AesCipher> encryptor = new(aes, buffer);
		byte[] ciphertext = new byte[plaintext.Length];
		byte[] tag = new byte[TTag.Size];
		CcmUtils.Encrypt<TTag, BufferedCcmBlockEncryptor<AesCipher>>(encryptor, nonce, plaintext, ciphertext, tag, associatedData);

		byte[] recovered = new byte[plaintext.Length];
		bool authenticated = CcmUtils.TryDecrypt<TTag, BufferedCcmBlockEncryptor<AesCipher>>(encryptor, nonce, ciphertext, tag, recovered, associatedData);

		byte[] badTag = tag.ToArray();
		badTag[0] ^= 1;
		byte[] rejected = new byte[plaintext.Length];
		rejected.AsSpan().Fill(DestinationSentinel);
		bool forged = CcmUtils.TryDecrypt<TTag, BufferedCcmBlockEncryptor<AesCipher>>(encryptor, nonce, ciphertext, badTag, rejected, associatedData);
		return (ciphertext, tag, authenticated, recovered, forged, rejected);
	}

	private static bool IsUnchanged(byte[] buffer)
	{
		return !buffer.AsSpan().ContainsAnyExcept(DestinationSentinel);
	}
}
