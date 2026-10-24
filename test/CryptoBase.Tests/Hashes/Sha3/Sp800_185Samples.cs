namespace CryptoBase.Tests.Hashes.Sha3;

public sealed record CShakeSample(int SecurityStrength, byte[] Data, string Customization, string Output)
{
	public int Rate => 200 - SecurityStrength / 4;
}

public sealed record KmacSample(int SecurityStrength, bool Xof, byte[] Key, byte[] Data, string Customization, string Output)
{
	public int Rate => 200 - SecurityStrength / 4;
}

// The NIST examples for SP 800-185, transcribed from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/cSHAKE_samples.pdf, KMAC_samples.pdf and KMACXOF_samples.pdf. Every cSHAKE example has an empty function name; a KMAC customization string printed as "(null)" is empty here.
// The customization strings are ASCII and the outputs hexadecimal; the output length is the requested length L.
public static class Sp800_185Samples
{
	// 00 01 02 03, and the 200 bytes 00 01 ... C7.
	private static readonly byte[] ShortData = Sequence(0x00, 4);
	private static readonly byte[] LongData = Sequence(0x00, 200);

	// 40 41 ... 5F
	private static readonly byte[] Key = Sequence(0x40, 32);

	public static IEnumerable<CShakeSample> CShake =>
	[
		new(128, ShortData, "Email Signature", "C1C36925B6409A04F1B504FCBCA9D82B4017277CB5ED2B2065FC1D3814D5AAF5"),
		new(128, LongData, "Email Signature", "C5221D50E4F822D96A2E8881A961420F294B7B24FE3D2094BAED2C6524CC166B"),
		new(256, ShortData, "Email Signature", "D008828E2B80AC9D2218FFEE1D070C48B8E4C87BFF32C9699D5B6896EEE0EDD164020E2BE0560858D9C00C037E34A96937C561A74C412BB4C746469527281C8C"),
		new(256, LongData, "Email Signature", "07DC27B11E51FBAC75BC7B3C1D983E8B4B85FB1DEFAF218912AC86430273091727F42B17ED1DF63E8EC118F04B23633C1DFB1574C8FB55CB45DA8E25AFB092BB")
	];

	public static IEnumerable<KmacSample> Kmac =>
	[
		new(128, false, Key, ShortData, "", "E5780B0D3EA6F7D3A429C5706AA43A00FADBD7D49628839E3187243F456EE14E"),
		new(128, false, Key, ShortData, "My Tagged Application", "3B1FBA963CD8B0B59E8C1A6D71888B7143651AF8BA0A7070C0979E2811324AA5"),
		new(128, false, Key, LongData, "My Tagged Application", "1F5B4E6CCA02209E0DCB5CA635B89A15E271ECC760071DFD805FAA38F9729230"),
		new(256, false, Key, ShortData, "My Tagged Application", "20C570C31346F703C9AC36C61C03CB64C3970D0CFC787E9B79599D273A68D2F7F69D4CC3DE9D104A351689F27CF6F5951F0103F33F4F24871024D9C27773A8DD"),
		new(256, false, Key, LongData, "", "75358CF39E41494E949707927CEE0AF20A3FF553904C86B08F21CC414BCFD691589D27CF5E15369CBBFF8B9A4C2EB17800855D0235FF635DA82533EC6B759B69"),
		new(256, false, Key, LongData, "My Tagged Application", "B58618F71F92E1D56C1B8C55DDD7CD188B97B4CA4D99831EB2699A837DA2E4D970FBACFDE50033AEA585F1A2708510C32D07880801BD182898FE476876FC8965")
	];

	public static IEnumerable<KmacSample> KmacXof =>
	[
		new(128, true, Key, ShortData, "", "CD83740BBD92CCC8CF032B1481A0F4460E7CA9DD12B08A0C4031178BACD6EC35"),
		new(128, true, Key, ShortData, "My Tagged Application", "31A44527B4ED9F5C6101D11DE6D26F0620AA5C341DEF41299657FE9DF1A3B16C"),
		new(128, true, Key, LongData, "My Tagged Application", "47026C7CD793084AA0283C253EF658490C0DB61438B8326FE9BDDF281B83AE0F"),
		new(256, true, Key, ShortData, "My Tagged Application", "1755133F1534752AAD0748F2C706FB5C784512CAB835CD15676B16C0C6647FA96FAA7AF634A0BF8FF6DF39374FA00FAD9A39E322A7C92065A64EB1FB0801EB2B"),
		new(256, true, Key, LongData, "", "FF7B171F1E8A2B24683EED37830EE797538BA8DC563F6DA1E667391A75EDC02CA633079F81CE12A25F45615EC89972031D18337331D24CEB8F8CA8E6A19FD98B"),
		new(256, true, Key, LongData, "My Tagged Application", "D5BE731C954ED7732846BB59DBE3A8E30F83E77A4BFF4459F2F1C2B4ECEBB8CE67BA01C62E8AB8578D2D499BD1BB276768781190020A306A97DE281DCC30305D")
	];

	private static byte[] Sequence(byte first, int length)
	{
		byte[] bytes = new byte[length];

		for (int i = 0; i < length; ++i)
		{
			bytes[i] = (byte)(first + i);
		}

		return bytes;
	}
}
