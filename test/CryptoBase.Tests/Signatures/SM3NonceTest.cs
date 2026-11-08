using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.SM9;
using CryptoBase.Signatures;
using System.Numerics;

namespace CryptoBase.Tests.Signatures;

// The nonces of SM2 and SM9 signatures: the first two candidates for empty and for 32 bytes of additional data, and the reduction of 512 bits mod n − 1 against BigInteger.
public class SM3NonceTest
{
	private static readonly byte[] AdditionalData = [.. Enumerable.Range(1, 32).Select(static i => (byte)i)];

	// d of the key of SM2InteropTest and e mod n of "message" with the default ID.
	[Test]
	public async Task CandidatesOfSM2MatchKnownAnswers()
	{
		string[] candidates = Candidates<SM2Order>("FF43D8DAF6177147291CF12497B160B008BC941A90B2A1DC3E3D596CF5BC95AE", "A72016DF5E20022ECCEECE81027F9CC0E8088829537747D86211153769829DB8");

		await Assert.That(candidates).IsEquivalentTo(
		[
			"553657D1DEB47A44B87571B5FBA559ECFEC491429F2AC5073F37AA3D5D18EB1F",
			"4EEE24184AAADADC18BD53E6DEBCAA2B8B73CB2C1F1F92D50413F477748EE357",
			"512E9A6BE95274FDAEF1456B2B212F898CE964ED97AFEF76E3E5EC050758988E",
			"7FEA49EC94C63FC8365262BCFF6B12CAF454C600200C252B052E78A07B782A36",
		], CollectionOrdering.Matching);
	}

	// The x-coordinate of dsA of GM/T 0044.5, A.2, and SM3(0x02 ‖ M ‖ 00000001) mod N for its message.
	[Test]
	public async Task CandidatesOfSM9MatchKnownAnswers()
	{
		string[] candidates = Candidates<SM9Order>("A5702F05CF1315305E2D6EB64B0DEB923DB1A0BCF0CAFF90523AC8754AA69820", "5B497E98AB0841327FC59AB8C587C55546192C9059062D412027707D1196CAE2");

		await Assert.That(candidates).IsEquivalentTo(
		[
			"1AFE35AA7651956CE86A4504A7EAE830FEE7DB50CD264D053DBFB5633829D735",
			"4C72E44FDA723A9E16BF17564AB9DC95BF5E797F8FAB7AB41DA50C36AA5F0FE2",
			"6E33B221D8C22373BBBB6619744B635BF445BCFB8E96C56B56A8C1B404F549FC",
			"36248C086BD68ADA591AC6A4B2A03AB774DFB0C81F39E0DFAA8E64B9F979B987",
		], CollectionOrdering.Matching);
	}

	// For both orders: ⌊2^512/(n − 1)⌋ = 2^256 + NonceReciprocal, with a fraction below 1 − 2^−63, which keeps the estimate of Reduce at most one short; and the values at the edges of the reduction and random ones.
	[Test]
	public async Task ReductionMatchesBigInteger()
	{
		List<string> failures = [];
		Check<SM2Order>(failures);
		Check<SM9Order>(failures);

		await Assert.That(failures).IsEmpty();
	}

	private static string[] Candidates<TOrder>(string key, string hash) where TOrder : unmanaged, ISM3NonceOrder
	{
		List<string> candidates = [];

		foreach (byte[] additionalData in (byte[][])[[], AdditionalData])
		{
			SM3Nonce<TOrder> nonce = default;
			nonce.Initialize(Convert.FromHexString(key), Convert.FromHexString(hash), additionalData);

			for (int i = 0; i < 2; ++i)
			{
				nonce.Next(out FieldElement<TOrder> candidate);
				byte[] encoded = new byte[TOrder.ByteLength];
				FieldElement<TOrder>.Export(in candidate, encoded);
				candidates.Add(Convert.ToHexString(encoded));
			}

			nonce.Clear();
		}

		return [.. candidates];
	}

	private static void Check<TOrder>(List<string> failures) where TOrder : unmanaged, ISM3NonceOrder
	{
		string name = typeof(TOrder).Name;
		BigInteger m = ToInteger(TOrder.Modulus) - 1;
		BigInteger power = BigInteger.One << 512;
		BigInteger last = (power - 1) / m * m;

		if (power / m != (BigInteger.One << 256) + ToInteger(TOrder.NonceReciprocal))
		{
			failures.Add($"{name}: the reciprocal");
		}

		if (power % m << 63 >= ((BigInteger.One << 63) - 1) * m)
		{
			failures.Add($"{name}: the fraction of the reciprocal");
		}

		List<BigInteger> values = [0, 1, m - 1, m, m + 1, 2 * m - 1, 2 * m, (BigInteger.One << 256) - 1, BigInteger.One << 256, (BigInteger.One << 255) * m - 1, (BigInteger.One << 255) * m, last - 1, last, power - 1];
		Random random = new(32918);

		for (int i = 0; i < 4096; ++i)
		{
			byte[] bytes = new byte[64];
			random.NextBytes(bytes);
			values.Add(new BigInteger(bytes, true, true));
		}

		foreach (BigInteger value in values)
		{
			byte[] encoded = new byte[64];
			byte[] minimal = value.ToByteArray(true, true);
			minimal.CopyTo(encoded, encoded.Length - minimal.Length);
			SM3Nonce<TOrder>.Reduce(encoded, out FieldElement<TOrder> result);

			if (ToInteger(FieldElement<TOrder>.GetLimbs(in result)) != value % m + 1)
			{
				failures.Add($"{name}: {value:X}");
			}
		}
	}

	private static BigInteger ToInteger(ReadOnlySpan<ulong> limbs)
	{
		BigInteger value = BigInteger.Zero;

		for (int i = limbs.Length - 1; i >= 0; --i)
		{
			value = value << 64 | limbs[i];
		}

		return value;
	}
}
