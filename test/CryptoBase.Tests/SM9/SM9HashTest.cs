using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.SM9;
using CryptoBase.Kdf;
using CryptoBase.SM9;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9Reference;
using static CryptoBase.Tests.SM9.SM9TestUtils;

namespace CryptoBase.Tests.SM9;

// H1 and H2 of GM/T 0044.2-2016, Sec. 5.4.2, against the BigInteger reference.
public class SM9HashTest
{
	// (Ha mod (N − 1)) + 1 for Ha of 320 bits: the multiples of N − 1 and their neighbours, where the Barrett quotient falls short by most, the largest Ha, and random ones.
	[Test]
	public async Task ReductionMatchesTheReference()
	{
		BigInteger m = N - 1;
		BigInteger bound = BigInteger.One << 320;
		List<BigInteger> values = [0, 1, m - 1, m, m + 1, 2 * m - 1, 2 * m, (BigInteger.One << 256) - 1, BigInteger.One << 256, BigInteger.One << 319, bound - 1];

		foreach (BigInteger quotient in (BigInteger[])[1, 2, 3, BigInteger.One << 63, (BigInteger.One << 64) - 1, BigInteger.One << 64, (bound - 1) / m])
		{
			foreach (BigInteger remainder in (BigInteger[])[0, 1, m - 2, m - 1])
			{
				values.Add(quotient * m + remainder);
			}
		}

		Random random = new(9);

		for (int i = 0; i < 2000; ++i)
		{
			byte[] bytes = new byte[41];
			random.NextBytes(bytes.AsSpan(0, 40));
			values.Add(new BigInteger(bytes) % bound);
		}

		List<string> failures = [];

		foreach (BigInteger value in values.Where(value => value >= 0 && value < bound))
		{
			byte[] encoded = Encode(value, 40);
			SM9Hash.Reduce(encoded, out FieldElement<SM9Order> h);

			if (Value(in h) != value % m + 1)
			{
				failures.Add($"{value:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// IDs and messages around the SM3 block of 64 bytes, whose padding takes a block of its own from 56 bytes on.
	[Test]
	public async Task HashesMatchTheReference()
	{
		List<string> failures = [];

		foreach (int length in (int[])[0, 1, 50, 51, 54, 55, 56, 63, 64, 100, 1000])
		{
			byte[] z = [.. Enumerable.Range(0, length).Select(static i => (byte)(i * 13 + 5))];

			foreach (byte hid in (byte[])[0x01, 0x02, 0x03, 0xFF])
			{
				SM9Hash.H1(z, hid, out FieldElement<SM9Order> h1);

				if (Value(in h1) != ReferenceHash(0x01, [.. z, hid]))
				{
					failures.Add($"H1 of {length} bytes and hid {hid}");
				}
			}

			SM9Hash.StartH2(z, out SM3KdfState state);
			state.Append([0xA5]);
			SM9Hash.Finish(in state, out FieldElement<SM9Order> h2);

			if (Value(in h2) != ReferenceHash(0x02, [.. z, 0xA5]))
			{
				failures.Add($"H2 of {length} bytes");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	private static BigInteger Value(in FieldElement<SM9Order> scalar)
	{
		byte[] bytes = new byte[32];
		FieldElement<SM9Order>.Export(in scalar, bytes);
		return new BigInteger(bytes, true, true);
	}
}
