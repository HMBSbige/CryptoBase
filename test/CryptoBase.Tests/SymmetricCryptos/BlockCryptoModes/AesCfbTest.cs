using CryptoBase.Abstractions.SymmetricCryptos;
using CryptoBase.SymmetricCryptos.StreamCryptos;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.SymmetricCryptos.BlockCryptoModes;

public class AesCfbTest
{
	private const string IvHex = "000102030405060708090A0B0C0D0E0F";
	private const string PlaintextHex = "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E5130C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710";

	/// <summary>
	/// NIST SP 800-38A, CFB128 examples.
	/// </summary>
	[Test]
	[Arguments("2B7E151628AED2A6ABF7158809CF4F3C", "3B3FD92EB72DAD20333449F8E83CFB4AC8A64537A0B3A93FCDE3CDAD9F1CE58B26751F67A3CBB140B1808CF187A4F4DFC04B05357C5D1C0EEAC4C66F9FF7F2E6")]
	[Arguments("8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B", "CDC80D6FDDF18CAB34C25909C99A417467CE7F7F81173621961A2B70171D3D7A2E1E8A1DD59B88B1C8E60FED1EFAC4C9C05F9F9CA9834FA042AE8FBA584B09FF")]
	[Arguments("603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4", "DC7E84BFDA79164B7ECD8486985D386039FFED143B28B1C832113C6331E5407BDF10132415E54B92A13ED0A8267AE2F975A385741AB9CEF82031623D55B1E471")]
	public async Task StandardVectorsCoverEveryAesKeySize(string keyHex, string ciphertextHex)
	{
		byte[] key = Convert.FromHexString(keyHex);
		byte[] iv = Convert.FromHexString(IvHex);
		byte[] plaintext = Convert.FromHexString(PlaintextHex);
		byte[] ciphertext = Convert.FromHexString(ciphertextHex);

		await VerifyStreamVector(StreamCryptoCreate.AesCfb(true, key, iv), "AES-CFB", plaintext, ciphertext);
		await VerifyStreamVector(StreamCryptoCreate.AesCfb(false, key, iv), "AES-CFB", ciphertext, plaintext);
	}

	[Test]
	[Arguments(false)]
	[Arguments(true)]
	public async Task ArbitraryChunkingMatchesOneShot(bool isEncryption)
	{
		byte[] key = CreateDeterministicSource(32);
		byte[] iv = CreateDeterministicSource(16);
		byte[] source = CreateDeterministicSource(257);
		byte[] expected = new byte[source.Length];
		byte[] actual = new byte[source.Length];
		using IStreamCrypto oneShot = StreamCryptoCreate.AesCfb(isEncryption, key, iv);
		using IStreamCrypto chunked = StreamCryptoCreate.AesCfb(isEncryption, key, iv);

		oneShot.Update(source, expected);
		int offset = 0;

		foreach (int length in (int[])[1, 15, 16, 17, 31, 64, 113])
		{
			chunked.Update(source.AsSpan(offset, length), actual.AsSpan(offset, length));
			offset += length;
		}

		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}
}
