using System.Text;

namespace CryptoBase.Tests.Hashes.Sha3;

// Checks the SP 800-185 transcription in KeccakReference against the NIST examples, so that it can stand in as an oracle for any input.
public class Sp800_185ReferenceTest
{
	[Test]
	[MethodDataSource(typeof(Sp800_185Samples), nameof(Sp800_185Samples.CShake))]
	public async Task CShakeMatchesNistSamples(CShakeSample sample)
	{
		byte[] expected = Convert.FromHexString(sample.Output);
		byte[] actual = KeccakReference.CShake(sample.Data, sample.Rate, [], Encoding.ASCII.GetBytes(sample.Customization), expected.Length);

		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	[Test]
	[MethodDataSource(typeof(Sp800_185Samples), nameof(Sp800_185Samples.Kmac))]
	[MethodDataSource(typeof(Sp800_185Samples), nameof(Sp800_185Samples.KmacXof))]
	public async Task KmacMatchesNistSamples(KmacSample sample)
	{
		byte[] expected = Convert.FromHexString(sample.Output);
		byte[] actual = KeccakReference.Kmac(sample.Key, sample.Data, sample.Rate, Encoding.ASCII.GetBytes(sample.Customization), expected.Length, sample.Xof);

		await Assert.That(actual).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}

	// The "bytepad data" of the cSHAKE128 examples, which zero-fills the encoded strings to the 168-byte rate.
	[Test]
	public async Task BytePadMatchesNistSample()
	{
		byte[] encoded = TestUtils.Concat(KeccakReference.EncodeString([]), KeccakReference.EncodeString("Email Signature"u8));
		byte[] expected = new byte[168];
		Convert.FromHexString("01A801000178456D61696C205369676E6174757265").CopyTo(expected, 0);

		await Assert.That(KeccakReference.BytePad(encoded, 168)).IsEquivalentTo(expected, CollectionOrdering.Matching);
	}
}
