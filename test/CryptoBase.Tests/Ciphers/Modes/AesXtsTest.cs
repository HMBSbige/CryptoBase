using CryptoBase.Ciphers.Blocks.Aes;
using CryptoBase.Ciphers.Modes;
using System.Diagnostics.CodeAnalysis;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Ciphers.Modes;

public class AesXtsTest
{
	public static IEnumerable<(string, UInt128, string, string)> StandardCases()
	{
		yield return
		(
			"a3e40d5bd4b6bbedb2d18c700ad2db2210c81190646d673cbca53f133eab373c",
			141,
			"20e0719405993f09a66ae5bb500e562c",
			"74623551210216ac926b9650b6d3fa52"
		);
		yield return
		(
			"fb46fb3cab7f67ad5207bc232c50dcbb24dbd1564590855d4cb777b3ba6431c3",
			117,
			"46409f7426eb4e3d33480534b80fe6e09fed6583907eb83c84",
			"a19d9b3209d388740a581975091fe26deecbb0f117c22b0ae4"
		);
		yield return
		(
			"ef010ca1a3663e32534349bc0bae62232a1573348568fb9ef41768a7674f507a727f98755397d0e0aa32f830338cc7a926c773f09e57b357cd156afbca46e1a0",
			187,
			"ed98e01770a853b49db9e6aaf88f0a41b9b56e91a5a2b11d40529254f5523e75",
			"ca20c55e8dc149687d2541de39c3df6300bb5a163c10ced3666b1357db8bd39d"
		);
	}

	[Test]
	[MethodDataSource(nameof(StandardCases))]
	public async Task StandardVectorsCoverBothKeySizesAndCiphertextStealing(string keyHex, UInt128 dataUnitSequenceNumber, string plaintextHex, string ciphertextHex)
	{
		byte[] iv = new byte[16];
		XtsMode.GetIV(iv, dataUnitSequenceNumber);
		await VerifyVector(keyHex, iv, plaintextHex, ciphertextHex);
	}

	[Test]
	public async Task Aligned512ByteOpenSslVectorCoversBatchBackends()
	{
		const string key = "af161950be7fa980243bf657c865a5fd2585e5f67cd04ef32563127bade41719";
		byte[] iv = Convert.FromHexString("a8e7ea0ac39591fbc7cb840164f0fb4a");
		const string plaintext = "cada9063872806743ecf6d6b8a0d367cd70dad99e81794cbbf38cd6e4c9b776ca291d173a23efc1d948360e2a89e0a776f03bce77088c88643b0015de11de211120122149eb700415de679c9fd90a7190737c2c7e193df854aac8051b828fc6cc7a9a192efbafb4e2b3e31e5b7c74f211342b6c44cf161337437e6a147f8300bbec0cd25c3c01766d06ca7216b0e7dd4c95d9006e9c034211903e98e7e19e5f9b8ed0cc66a50399ada5afb9614c0aa763d585b5600e327297c4b5a25a33d44f178938f9b81fdc61dba83ed2f6c64cc3363ee5f555668d0f137d2639911ea562719491fb39ee786423e4af3e1d62abc5b843dfb48b6f05cb433bc052871bc3d968c8f9714af850efcbc72895b898bc521587ad4784012dfe2a1c3e727bd836450605f2221af27cb92693013a5d4a65e5b20daa7aa83584604818443c73a4c16974116f41e06a5e12fd5c6b42dc187929c8f41a1984bbe7a70bb8ed8247014d3fb8884615ae4dcf59d90444ecd279790748e48a21c2e81c0f7691db238233dc77356e946383d3dae66bc8ac15eaca75781ee43bfb5d9b2dbf3c01014581d3e7a5c38db993f7c2b5cd34cf9a3391c0c0716c55520826110ddbc2a3c3695901494203ed67a42bf881aa21bdbecec8abb95014fc7718391bf54fb357ee984b9a95be2a0eb7f4a549fe25c1f5ca3cafcd1d0959c88a8ca991b5d7dc24febea59f77d50";
		const string ciphertext = "dcedd094dd03d116c3b3768bc32ec1a39366bd61d7ba0baf5f164093c522429728b8db5eaf2170bdfabf5fabe48e7a7373963db6b9a19b01d2de74a56c1836ca98f36ced9bd004f68abbe24e87f3c7379a4822bd6ef2df83b734c74a24e549f9a420c4077750c688de372af838eefeb0884a8dac33518d507eb649c3255d61bd99688a8f2f3492ecca9390f832e31a1a2f7cd270bab9813d82fa5261aa04d8920ee3fabf9fe25ab60dbbaeb0b2b59d15e66eda837e7b554a26f369f6734ecc63e24623696bfe52eb3c24609706f4a66adc6ce903f950abe4bbf2448fe6e16a2d5192ba3a9ab9929e0748bf04d6dd39817dbd487e51b348fde9e0290374b259a135c40ec25f295c4624ced030c0ec0db47233f61785dc81afc883a0e1227962492efbe7c7aab6147179eb9e75d8792da3d5591e74d152de57e5454d208e66a26d284f5ee33f5f5bd834b7f6dfaf0084a6e4b9e9a6deaf55c4c2321d4c561b7cd5ef6f3890310b0df8b515cd127d6c287e9077cab4d8997df7e54f7d0d84585636f53b1adf65ca0782d12aeb94835a172c2e92e7357dcdd666d20eb752c37a475f4be8f11553a226d88671963ff51f14b21dc92956c8bab09555338a7173b63071bd5e864fdea89c1026b923c1b12b46fc194f8b3431c0c25553e378321cc2dd52ff4725a123a8c75417dac058c9ed534f35adec1624a31c4afdce72b9d1b7524f";

		await VerifyVector(key, iv, plaintext, ciphertext);
	}

	[Test]
	[Arguments
	(
		"000102030405060708090a0b0c0d0e0f",
		"e15ae9891638794e54332fb2d765cad7"
	)]
	[Arguments
	(
		"000102030405060708090a0b0c0d0e0f10",
		"1d65158c3a3935c7ea9cede3a9a62e31e1"
	)]
	[Arguments
	(
		"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
		"38ca49f611a659bf0b6dbc3ae40a8c71e15ae9891638794e54332fb2d765ca"
	)]
	public async Task ExactInPlaceMatchesOpenSslAtCiphertextStealingBoundaries(string plaintextHex, string ciphertextHex)
	{
		byte[] iv = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
		byte[] plaintext = Convert.FromHexString(plaintextHex);
		byte[] ciphertext = Convert.FromHexString(ciphertextHex);
		byte[] buffer = (byte[])plaintext.Clone();
		using XtsMode<AesCipher> crypto = XtsMode<AesCipher>.Create(Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));

		crypto.Encrypt(iv, buffer, buffer);
		await Assert.That(buffer).IsEquivalentTo(ciphertext, CollectionOrdering.Matching);
		crypto.Decrypt(iv, buffer, buffer);
		await Assert.That(buffer).IsEquivalentTo(plaintext, CollectionOrdering.Matching);
	}

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
	[Arguments(16, 2047)]
	[Arguments(16, 2048)]
	[Arguments(16, 2049)]
	[Arguments(32, 4097)]
	public async Task KeyFactoriesAndBatchBoundaries(int keyLength, int length)
	{
		byte[] key = CreateDeterministicSource(keyLength * 2);
		using XtsMode<AesCipher> combined = XtsMode<AesCipher>.Create(key);
		using XtsMode<AesCipher> separate = XtsMode<AesCipher>.Create(key.AsSpan(0, keyLength), key.AsSpan(keyLength));
		byte[] iv = CreateDeterministicSource(16);
		byte[] plaintext = CreateDeterministicSource(length);
		byte[] expected = new byte[length];
		byte[] output = new byte[length + 7];
		PrepareDestination(output);
		combined.Encrypt(iv, plaintext, expected);
		separate.Encrypt(iv, plaintext, output);
		await AssertOutput(output, expected);
		separate.Decrypt(iv, output.AsSpan(0, length), output);
		await AssertOutput(output, plaintext);
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

	private static async Task VerifyVector(string keyHex, byte[] iv, string plaintextHex, string ciphertextHex)
	{
		byte[] key = Convert.FromHexString(keyHex);
		byte[] plaintext = Convert.FromHexString(plaintextHex);
		byte[] ciphertext = Convert.FromHexString(ciphertextHex);
		byte[] destination = new byte[plaintext.Length + 1];
		destination.AsSpan().Fill(DestinationSentinel);
		using XtsMode<AesCipher> crypto = XtsMode<AesCipher>.Create(key);

		crypto.Encrypt(iv, plaintext, destination);

		await AssertOutput(destination, ciphertext);

		destination.AsSpan().Fill(DestinationSentinel);
		crypto.Decrypt(iv, ciphertext, destination);
		await AssertOutput(destination, plaintext);
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
