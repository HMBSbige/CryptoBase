using CryptoBase.Abstractions.Hashes;
using CryptoBase.Abstractions.Signatures;
using CryptoBase.EllipticCurves;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Signatures.Ecdsa;
using CryptoBase.Tests.EllipticCurves;
using System.Formats.Asn1;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using static CryptoBase.Tests.Signatures.Ecdsa.EcdsaTestUtils;

namespace CryptoBase.Tests.Signatures.Ecdsa;

internal class EcdsaKnownAnswerTest
{
	private static readonly DeterministicKey P256Key = new
	(
		"C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
		"60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6",
		"7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299"
	);

	private static readonly DeterministicKey P384Key = new
	(
		"6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
		"EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13",
		"8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720"
	);

	// The values of P-521 are written in 131 hexadecimal digits, one short of 66 bytes.
	private static readonly DeterministicKey P521Key = new
	(
		"0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75CAA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83538",
		"1894550D0785932E00EAA23B694F213F8C3121F86DC97A04E5A7167DB4E5BCD371123D46E45DB6B5D5370A7F20FB633155D38FFA16D2BD761DCAC474B9A2F5023A4",
		"0493101C962CD4D2FDDF782285E64584139C2F91B47F87FF82354D6630F746A28A0DB25741B5B34A828008B22ACC23F924FAAFBD4D33F81EA66956DFEAA2BFDFCF5"
	);

	public static IEnumerable<DeterministicVector> P256Vectors()
	{
		yield return new DeterministicVector
		(
			SignatureAlgorithm.EcdsaSha256,
			"sample",
			"A6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60",
			"EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
			"F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8"
		);

		yield return new DeterministicVector
		(
			SignatureAlgorithm.EcdsaSha384,
			"sample",
			"09F634B188CEFD98E7EC88B1AA9852D734D0BC272F7D2A47DECC6EBEB375AAD4",
			"0EAFEA039B20E9B42309FB1D89E213057CBF973DC0CFC8F129EDDDC800EF7719",
			"4861F0491E6998B9455193E34E7B0D284DDD7149A74B95B9261F13ABDE940954"
		);

		yield return new DeterministicVector
		(
			SignatureAlgorithm.EcdsaSha512,
			"sample",
			"5FA81C63109BADB88C1F367B47DA606DA28CAD69AA22C4FE6AD7DF73A7173AA5",
			"8496A60B5E9B47C825488827E0495B0E3FA109EC4568FD3F8D1097678EB97F00",
			"2362AB1ADBE2B8ADF9CB9EDAB740EA6049C028114F2460F96554F61FAE3302FE"
		);

		yield return new DeterministicVector
		(
			SignatureAlgorithm.EcdsaSha256,
			"test",
			"D16B6AE827F17175E040871A1C7EC3500192C4C92677336EC2537ACAEE0008E0",
			"F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367",
			"019F4113742A2B14BD25926B49C649155F267E60D3814B4C0CC84250E46F0083"
		);

		yield return new DeterministicVector
		(
			SignatureAlgorithm.EcdsaSha384,
			"test",
			"16AEFFA357260B04B1DD199693960740066C1A8F3E8EDD79070AA914D361B3B8",
			"83910E8B48BB0C74244EBDF7F07A1C5413D61472BD941EF3920E623FBCCEBEB6",
			"8DDBEC54CF8CD5874883841D712142A56A8D0F218F5003CB0296B6B509619F2C"
		);

		yield return new DeterministicVector
		(
			SignatureAlgorithm.EcdsaSha512,
			"test",
			"6915D11632ACA3C40D5D51C08DAF9C555933819548784480E93499000D9F0B7F",
			"461D93F31B6540894788FD206C07CFA0CC35F46FA3C91816FFF1040AD1581A04",
			"39AF9F15DE0DB8D97E72719C74820D304CE5226E32DEDAE67519E840D1194E55"
		);
	}

	public static IEnumerable<DeterministicVector> P384Vectors()
	{
		yield return new DeterministicVector
		(
			SignatureAlgorithm.EcdsaSha256,
			"sample",
			"180AE9F9AEC5438A44BC159A1FCB277C7BE54FA20E7CF404B490650A8ACC414E375572342863C899F9F2EDF9747A9B60",
			"21B13D1E013C7FA1392D03C5F99AF8B30C570C6F98D4EA8E354B63A21D3DAA33BDE1E888E63355D92FA2B3C36D8FB2CD",
			"F3AA443FB107745BF4BD77CB3891674632068A10CA67E3D45DB2266FA7D1FEEBEFDC63ECCD1AC42EC0CB8668A4FA0AB0"
		);

		yield return new DeterministicVector
		(
			SignatureAlgorithm.EcdsaSha384,
			"sample",
			"94ED910D1A099DAD3254E9242AE85ABDE4BA15168EAF0CA87A555FD56D10FBCA2907E3E83BA95368623B8C4686915CF9",
			"94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46",
			"99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8"
		);

		yield return new DeterministicVector
		(
			SignatureAlgorithm.EcdsaSha512,
			"sample",
			"92FC3C7183A883E24216D1141F1A8976C5B0DD797DFA597E3D7B32198BD35331A4E966532593A52980D0E3AAA5E10EC3",
			"ED0959D5880AB2D869AE7F6C2915C6D60F96507F9CB3E047C0046861DA4A799CFE30F35CC900056D7C99CD7882433709",
			"512C8CCEEE3890A84058CE1E22DBC2198F42323CE8ACA9135329F03C068E5112DC7CC3EF3446DEFCEB01A45C2667FDD5"
		);

		yield return new DeterministicVector
		(
			SignatureAlgorithm.EcdsaSha256,
			"test",
			"0CFAC37587532347DC3389FDC98286BBA8C73807285B184C83E62E26C401C0FAA48DD070BA79921A3457ABFF2D630AD7",
			"6D6DEFAC9AB64DABAFE36C6BF510352A4CC27001263638E5B16D9BB51D451559F918EEDAF2293BE5B475CC8F0188636B",
			"2D46F3BECBCC523D5F1A1256BF0C9B024D879BA9E838144C8BA6BAEB4B53B47D51AB373F9845C0514EEFB14024787265"
		);

		yield return new DeterministicVector
		(
			SignatureAlgorithm.EcdsaSha384,
			"test",
			"015EE46A5BF88773ED9123A5AB0807962D193719503C527B031B4C2D225092ADA71F4A459BC0DA98ADB95837DB8312EA",
			"8203B63D3C853E8D77227FB377BCF7B7B772E97892A80F36AB775D509D7A5FEB0542A7F0812998DA8F1DD3CA3CF023DB",
			"DDD0760448D42D8A43AF45AF836FCE4DE8BE06B485E9B61B827C2F13173923E06A739F040649A667BF3B828246BAA5A5"
		);

		yield return new DeterministicVector
		(
			SignatureAlgorithm.EcdsaSha512,
			"test",
			"3780C4F67CB15518B6ACAE34C9F83568D2E12E47DEAB6C50A4E4EE5319D1E8CE0E2CC8A136036DC4B9C00E6888F66B6C",
			"A0D5D090C9980FAF3C2CE57B7AE951D31977DD11C775D314AF55F76C676447D06FB6495CD21B4B6E340FC236584FB277",
			"976984E59B4C77B0E8E4460DCA3D9F20E07B9BB1F63BEEFAF576F6B2E8B224634A2092CD3792E0159AD9CEE37659C736"
		);
	}

	public static IEnumerable<DeterministicVector> P521Vectors()
	{
		yield return new DeterministicVector
		(
			SignatureAlgorithm.EcdsaSha256,
			"sample",
			"0EDF38AFCAAECAB4383358B34D67C9F2216C8382AAEA44A3DAD5FDC9C32575761793FEF24EB0FC276DFC4F6E3EC476752F043CF01415387470BCBD8678ED2C7E1A0",
			"1511BB4D675114FE266FC4372B87682BAECC01D3CC62CF2303C92B3526012659D16876E25C7C1E57648F23B73564D67F61C6F14D527D54972810421E7D87589E1A7",
			"04A171143A83163D6DF460AAF61522695F207A58B95C0644D87E52AA1A347916E4F7A72930B1BC06DBE22CE3F58264AFD23704CBB63B29B931F7DE6C9D949A7ECFC"
		);

		yield return new DeterministicVector
		(
			SignatureAlgorithm.EcdsaSha384,
			"sample",
			"1546A108BC23A15D6F21872F7DED661FA8431DDBD922D0DCDB77CC878C8553FFAD064C95A920A750AC9137E527390D2D92F153E66196966EA554D9ADFCB109C4211",
			"1EA842A0E17D2DE4F92C15315C63DDF72685C18195C2BB95E572B9C5136CA4B4B576AD712A52BE9730627D16054BA40CC0B8D3FF035B12AE75168397F5D50C67451",
			"1F21A3CEE066E1961025FB048BD5FE2B7924D0CD797BABE0A83B66F1E35EEAF5FDE143FA85DC394A7DEE766523393784484BDF3E00114A1C857CDE1AA203DB65D61"
		);

		yield return new DeterministicVector
		(
			SignatureAlgorithm.EcdsaSha512,
			"sample",
			"1DAE2EA071F8110DC26882D4D5EAE0621A3256FC8847FB9022E2B7D28E6F10198B1574FDD03A9053C08A1854A168AA5A57470EC97DD5CE090124EF52A2F7ECBFFD3",
			"0C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F174E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E377FA",
			"0617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF282623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A67A"
		);

		yield return new DeterministicVector
		(
			SignatureAlgorithm.EcdsaSha256,
			"test",
			"01DE74955EFAABC4C4F17F8E84D881D1310B5392D7700275F82F145C61E843841AF09035BF7A6210F5A431A6A9E81C9323354A9E69135D44EBD2FCAA7731B909258",
			"00E871C4A14F993C6C7369501900C4BC1E9C7B0B4BA44E04868B30B41D8071042EB28C4C250411D0CE08CD197E4188EA4876F279F90B3D8D74A3C76E6F1E4656AA8",
			"0CD52DBAA33B063C3A6CD8058A1FB0A46A4754B034FCC644766CA14DA8CA5CA9FDE00E88C1AD60CCBA759025299079D7A427EC3CC5B619BFBC828E7769BCD694E86"
		);

		yield return new DeterministicVector
		(
			SignatureAlgorithm.EcdsaSha384,
			"test",
			"1F1FC4A349A7DA9A9E116BFDD055DC08E78252FF8E23AC276AC88B1770AE0B5DCEB1ED14A4916B769A523CE1E90BA22846AF11DF8B300C38818F713DADD85DE0C88",
			"14BEE21A18B6D8B3C93FAB08D43E739707953244FDBE924FA926D76669E7AC8C89DF62ED8975C2D8397A65A49DCC09F6B0AC62272741924D479354D74FF6075578C",
			"133330865C067A0EAF72362A65E2D7BC4E461E8C8995C3B6226A21BD1AA78F0ED94FE536A0DCA35534F0CD1510C41525D163FE9D74D134881E35141ED5E8E95B979"
		);

		yield return new DeterministicVector
		(
			SignatureAlgorithm.EcdsaSha512,
			"test",
			"16200813020EC986863BEDFC1B121F605C1215645018AEA1A7B215A564DE9EB1B38A67AA1128B80CE391C4FB71187654AAA3431027BFC7F395766CA988C964DC56D",
			"13E99020ABF5CEE7525D16B69B229652AB6BDF2AFFCAEF38773B4B7D08725F10CDB93482FDCC54EDCEE91ECA4166B2A7C6265EF0CE2BD7051B7CEF945BABD47EE6D",
			"1FBD0013C674AA79CB39849527916CE301C66EA7CE8B80682786AD60F98F7E78A19CA69EFF5C57400E3B3A0AD66CE0978214D13BAF4E9AC60752F7B155E2DE4DCE3"
		);
	}

	[Test]
	public async Task PrivateKeysGiveTheirPublicKeys()
	{
		using (Assert.Multiple())
		{
			await CheckPublicKey<EcdsaP256>(P256Key);
			await CheckPublicKey<EcdsaP384>(P384Key);
			await CheckPublicKey<EcdsaP521>(P521Key);
		}
	}

	[Test]
	[MethodDataSource(nameof(P256Vectors))]
	public Task NonceMatchesP256(DeterministicVector vector)
	{
		return CheckNonce<EcdsaP256, P256Order>(P256Key, vector);
	}

	[Test]
	[MethodDataSource(nameof(P384Vectors))]
	public Task NonceMatchesP384(DeterministicVector vector)
	{
		return CheckNonce<EcdsaP384, P384Order>(P384Key, vector);
	}

	[Test]
	[MethodDataSource(nameof(P521Vectors))]
	public Task NonceMatchesP521(DeterministicVector vector)
	{
		return CheckNonce<EcdsaP521, P521Order>(P521Key, vector);
	}

	[Test]
	[MethodDataSource(nameof(P256Vectors))]
	public Task SignatureMatchesP256(DeterministicVector vector)
	{
		return CheckSignature<EcdsaP256>(P256Key, vector);
	}

	[Test]
	[MethodDataSource(nameof(P384Vectors))]
	public Task SignatureMatchesP384(DeterministicVector vector)
	{
		return CheckSignature<EcdsaP384>(P384Key, vector);
	}

	[Test]
	[MethodDataSource(nameof(P521Vectors))]
	public Task SignatureMatchesP521(DeterministicVector vector)
	{
		return CheckSignature<EcdsaP521>(P521Key, vector);
	}

	// The 163-bit order drops the 5 rightmost bits of the hash and the candidates, and the first two candidates exceed it.
	[Test]
	public async Task RejectedCandidatesGiveWayToTheNext()
	{
		byte[] hash = SHA256.HashData("sample"u8);
		EcdsaEncoding<ExampleOrder>.ImportHash(hash, out FieldElement<ExampleOrder> truncated);
		byte[] encodedHash = new byte[ExampleOrder.ByteLength];
		FieldElement<ExampleOrder>.Export(in truncated, encodedHash);

		using (Assert.Multiple())
		{
			await Assert.That(Convert.ToHexString(encodedHash)).IsEqualTo("01795EDF0D54DB760F156D0DAC04C0322B3A204224");
			await Assert.That(Convert.ToHexString(DeriveNonce<ExampleOrder>(SignatureAlgorithm.EcdsaSha256, Convert.FromHexString("009A4D6792295A7F730FC3F2B49CBC0F62E862272F"), encodedHash, [], 0))).IsEqualTo("023AF4074C90A02B3FE61D286D5C87F425E6BDD81B");
		}
	}

	[Test]
	public async Task LaterNoncesAndAdditionalDataMatch()
	{
		CurveCase curve = CurveOf<EcdsaP256>();
		byte[] privateKey = Convert.FromHexString(P256Key.PrivateKey);
		byte[] hash = TruncatedHash(SHA256.HashData("sample"u8), curve.Order, curve.ScalarBitLength, curve.ScalarLength);
		byte[] additionalData = Convert.FromHexString("1328FA49A535A116B6B926F4C45F879068CCFB55DF0B45F527C7196A2A4C4379");

		using (Assert.Multiple())
		{
			await Assert.That(Convert.ToHexString(DeriveNonce<P256Order>(SignatureAlgorithm.EcdsaSha256, privateKey, hash, [], 1))).IsEqualTo("8E83DC490BC5FC4D5992BD63CD87F254ADFFCB930F8A8011702A88870F638FDB");
			await Assert.That(Convert.ToHexString(DeriveNonce<P256Order>(SignatureAlgorithm.EcdsaSha256, privateKey, hash, additionalData, 0))).IsEqualTo("74ED58690AE8F550889CD0FA2BC6BD5699BEF497DE82348232F31B9FD528691A");
		}
	}

	// The nonce of call index of Next, counting from 0. privateKey and hash are as long as n, the hash already truncated.
	internal static byte[] DeriveNonce<TOrder>(SignatureAlgorithm algorithm, byte[] privateKey, byte[] hash, byte[] additionalData, int index) where TOrder : unmanaged, IMontgomeryModulus
	{
		return algorithm switch
		{
			SignatureAlgorithm.EcdsaSha256 => DeriveNonce<Sha256Core, TOrder>(privateKey, hash, additionalData, index),
			SignatureAlgorithm.EcdsaSha384 => DeriveNonce<Sha384Core, TOrder>(privateKey, hash, additionalData, index),
			SignatureAlgorithm.EcdsaSha512 => DeriveNonce<Sha512Core, TOrder>(privateKey, hash, additionalData, index),
			_ => throw new NotSupportedException(algorithm.ToString())
		};
	}

	// Computed here rather than by the code under test.
	internal static byte[] TruncatedHash(byte[] hash, BigInteger n, int bitLength, int length)
	{
		BigInteger value = new(hash, isUnsigned: true, isBigEndian: true);
		int excess = 8 * hash.Length - bitLength;

		if (excess > 0)
		{
			value >>= excess;
		}

		return CurveCase.EncodeInteger(value % n, length);
	}

	private static byte[] DeriveNonce<THash, TOrder>(byte[] privateKey, byte[] hash, byte[] additionalData, int index) where THash : unmanaged, IHmacHashCore<THash> where TOrder : unmanaged, IMontgomeryModulus
	{
		EcdsaNonce<THash, TOrder> nonce = default;
		nonce.Initialize(privateKey, hash, additionalData);
		FieldElement<TOrder> k = default;

		for (int i = 0; i <= index; ++i)
		{
			nonce.Next(out k);
		}

		nonce.Clear();
		byte[] result = new byte[TOrder.ByteLength];
		FieldElement<TOrder>.Export(in k, result);
		return result;
	}

	private static async Task CheckPublicKey<T>(DeterministicKey key) where T : class, IEcdsa<T>
	{
		int length = T.PrivateKeyLength;
		using T imported = T.ImportPrivateKey(FromHex(key.PrivateKey, length));

		await Assert.That(Convert.ToHexString(ExportPublicKey(imported))).IsEqualTo("04" + Padded(key.PublicKeyX, length) + Padded(key.PublicKeyY, length)).Because(typeof(T).Name);
	}

	private static async Task CheckNonce<T, TOrder>(DeterministicKey key, DeterministicVector vector) where T : class, IEcdsa<T> where TOrder : unmanaged, IMontgomeryModulus
	{
		CurveCase curve = CurveOf<T>();
		int length = curve.ScalarLength;
		byte[] hash = TruncatedHash(Hash(vector.Algorithm, Encoding.UTF8.GetBytes(vector.Message)), curve.Order, curve.ScalarBitLength, length);

		await Assert.That(Convert.ToHexString(DeriveNonce<TOrder>(vector.Algorithm, FromHex(key.PrivateKey, length), hash, [], 0))).IsEqualTo(Padded(vector.K, length));
	}

	private static async Task CheckSignature<T>(DeterministicKey key, DeterministicVector vector) where T : class, IEcdsa<T>
	{
		int length = T.PrivateKeyLength;
		using T signer = T.ImportPrivateKey(FromHex(key.PrivateKey, length));
		using T verifier = T.ImportPublicKey([0x04, .. FromHex(key.PublicKeyX, length), .. FromHex(key.PublicKeyY, length)]);
		byte[] message = Encoding.UTF8.GetBytes(vector.Message);
		byte[] concatenated = Sign(signer, vector.Algorithm, message, [], EcdsaSignatureFormat.Concatenated);
		byte[] der = Sign(signer, vector.Algorithm, message, [], EcdsaSignatureFormat.Der);
		AsnDecoder.ReadSequence(der, AsnEncodingRules.DER, out int offset, out int contentLength, out _);
		ReadOnlySpan<byte> contents = der.AsSpan(offset, contentLength);
		BigInteger r = AsnDecoder.ReadInteger(contents, AsnEncodingRules.DER, out int consumed);
		BigInteger s = AsnDecoder.ReadInteger(contents.Slice(consumed), AsnEncodingRules.DER, out _);

		using (Assert.Multiple())
		{
			await Assert.That(Convert.ToHexString(concatenated)).IsEqualTo(Padded(vector.R, length) + Padded(vector.S, length));
			await Assert.That((r, s)).IsEqualTo((ModulusCase.Decode(FromHex(vector.R, length)), ModulusCase.Decode(FromHex(vector.S, length))));
			await Assert.That(verifier.Verify(vector.Algorithm, message, der)).IsTrue();
			await Assert.That(verifier.Verify(vector.Algorithm, message, concatenated, EcdsaSignatureFormat.Concatenated)).IsTrue();
		}
	}

	private static string Padded(string value, int length)
	{
		return value.PadLeft(2 * length, '0');
	}

	private static byte[] FromHex(string value, int length)
	{
		return Convert.FromHexString(Padded(value, length));
	}

	public sealed record DeterministicKey(string PrivateKey, string PublicKeyX, string PublicKeyY);

	public sealed record DeterministicVector(SignatureAlgorithm Algorithm, string Message, string K, string R, string S)
	{
		public override string ToString()
		{
			return $"{Algorithm}, \"{Message}\"";
		}
	}

	[InlineArray(3)]
	internal struct ExampleOrder : IMontgomeryModulus
	{
		private static readonly BigInteger Value = BigInteger.Parse("04000000000000000000020108A2E0CC0D99F8A5EF", System.Globalization.NumberStyles.HexNumber);
		private static readonly ulong[] ModulusLimbs = ToLimbs(Value);
		private static readonly ulong[] MontgomeryOneLimbs = ToLimbs((BigInteger.One << 192) % Value);
		private static readonly ulong[] RSquaredLimbs = ToLimbs((BigInteger.One << 384) % Value);
		private static readonly byte[] InversionChainBytes = BinaryChain(Value - 2);

		private ulong _limb;

		public static int LimbCount => 3;

		public static int ByteLength => 21;

		public static int BitLength => 163;

		public static ReadOnlySpan<ulong> Modulus => ModulusLimbs;

		public static ReadOnlySpan<ulong> MontgomeryOne => MontgomeryOneLimbs;

		public static ReadOnlySpan<ulong> RSquared => RSquaredLimbs;

		// Newton's iteration doubles the correct low bits of m⁻¹ from the 3 of m itself.
		public static ulong NegativeInverse
		{
			get
			{
				ulong m = ModulusLimbs[0];
				ulong inverse = m;

				for (int i = 0; i < 5; ++i)
				{
					inverse *= 2 - m * inverse;
				}

				return 0 - inverse;
			}
		}

		public static ReadOnlySpan<byte> InversionChain => InversionChainBytes;

		private static byte[] BinaryChain(BigInteger exponent)
		{
			List<byte> chain = [0];
			int squarings = 0;

			for (int bit = (int)exponent.GetBitLength() - 2; bit >= 0; --bit)
			{
				++squarings;

				if (!(exponent >> bit).IsEven)
				{
					chain.AddRange([(byte)squarings, 0]);
					squarings = 0;
				}
			}

			return [.. chain];
		}

		private static ulong[] ToLimbs(BigInteger value)
		{
			ulong[] limbs = new ulong[LimbCount];

			for (int i = 0; i < limbs.Length; ++i)
			{
				limbs[i] = (ulong)(value >> 64 * i & ulong.MaxValue);
			}

			return limbs;
		}
	}
}
