using CryptoBase.EllipticCurves.Curve448;
using System.Numerics;
using System.Runtime.InteropServices;
using static CryptoBase.Tests.EllipticCurves.Curve448.Curve448Reference;
using static CryptoBase.Tests.EllipticCurves.Curve448.Curve448TestUtils;
using static CryptoBase.Tests.EllipticCurves.Curve448.Field448TestUtils;

namespace CryptoBase.Tests.EllipticCurves.Curve448;

// The complete formulas take points of every order; the twisted ones only ever meet points of odd order.
public class Edwards448Test
{
	private const int RandomCount = 10;

	private static readonly EdwardsValue[] Torsion = TorsionPoints();

	private static readonly EdwardsValue TwistedBase = TwistedMultiply(Twist(Base), (L + 1) / 4);

	[Test]
	public async Task BaseIsThePointOfRfc8032()
	{
		byte[] encoded = new byte[Edwards448.EncodedLength];
		Edwards448.Encode(in Edwards448.Base, encoded);

		using (Assert.Multiple())
		{
			await Assert.That(ToValue(Edwards448.Base)).IsEqualTo(Base);
			await Assert.That(IsOnCurve(Base)).IsTrue();
			await Assert.That(Multiply(Base, L)).IsEqualTo(Identity);
			await Assert.That(Convert.ToHexStringLower(encoded)).IsEqualTo("14fa30f25b790898adc8d74e2c13bdfdc4397ce61cffd33ad7c2a0051e9c78874098a36c7373ea4b62c7c9563720768824bcb66e71463f6900");
		}
	}

	// Untwist ∘ Twist is multiplication by 4, so the twisted base is [1/4 mod L] of the twisted image of B.
	[Test]
	public async Task TwistedBaseUntwistsToBase()
	{
		EdwardsValue? twistedBase = ToValue(TwistedEdwards448.Base);
		TwistedEdwards448.Untwist(in Edwards448.AsProjective(in TwistedEdwards448.Base), out EdwardsCompletedPoint completed);
		Edwards448.ToExtended(in completed, out EdwardsPoint untwisted);
		EdwardsValue point = RandomPoint(new Random(1));

		using (Assert.Multiple())
		{
			await Assert.That(twistedBase).IsEqualTo(TwistedBase);
			await Assert.That(IsOnTwistedCurve(TwistedBase)).IsTrue();
			await Assert.That(TwistedMultiply(TwistedBase, L)).IsEqualTo(Identity);
			await Assert.That(Untwist(TwistedBase)).IsEqualTo(Base);
			await Assert.That(ToValue(untwisted)).IsEqualTo(Base);
			await Assert.That(Untwist(Twist(point))).IsEqualTo(Multiply(point, 4));
		}
	}

	[Test]
	public async Task GroupLawMatchesTheReference()
	{
		List<string> failures = [];
		Random random = new(2);
		List<EdwardsValue> points = [.. Torsion, Base, Negate(Base), Add(Base, Torsion[1])];

		for (int i = 0; i < RandomCount; ++i)
		{
			points.Add(RandomPoint(random));
		}

		foreach (EdwardsValue left in points)
		{
			EdwardsPoint p = ToPoint(left, 1 + RandomBelow(random, P - 1));
			Edwards448.Double(in p, out EdwardsPoint doubled);
			Edwards448.Negate(in p, out EdwardsPoint negated);
			Check(failures, $"Double {Show(left)}", doubled, Add(left, left));
			Check(failures, $"Negate {Show(left)}", negated, Negate(left));

			foreach (EdwardsValue right in points)
			{
				EdwardsPoint q = ToPoint(right, 1 + RandomBelow(random, P - 1));
				Edwards448.ToCached(in q, out EdwardsCachedPoint cached);
				Edwards448.Add(in p, in cached, out EdwardsCompletedPoint completed);
				Edwards448.ToExtended(in completed, out EdwardsPoint sum);
				Edwards448.Subtract(in p, in cached, out completed);
				Edwards448.ToExtended(in completed, out EdwardsPoint difference);
				Check(failures, $"Add {Show(left)}, {Show(right)}", sum, Add(left, right));
				Check(failures, $"Subtract {Show(left)}, {Show(right)}", difference, Add(left, Negate(right)));

				EdwardsAffinePoint[] affine = new EdwardsAffinePoint[1];
				Edwards448.ToAffineVariableTime([q], affine);
				Edwards448.AddAffine(in p, in affine[0], out completed);
				Edwards448.ToExtended(in completed, out sum);
				Edwards448.SubtractAffine(in p, in affine[0], out completed);
				Edwards448.ToExtended(in completed, out difference);
				Check(failures, $"AddAffine {Show(left)}, {Show(right)}", sum, Add(left, right));
				Check(failures, $"SubtractAffine {Show(left)}, {Show(right)}", difference, Add(left, Negate(right)));
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task FormulasTakeTheLargestTightLimbs()
	{
		List<string> failures = [];
		Random random = new(3);
		BigInteger largest = ValueOf(LargestTight);

		foreach (EdwardsValue value in (EdwardsValue[])[Base, Torsion[1], RandomPoint(random)])
		{
			EdwardsPoint p = ToPoint(value, largest);
			p.Z = LargestTight;
			Edwards448.Double(in p, out EdwardsPoint doubled);
			Check(failures, $"Double {Show(value)}", doubled, Add(value, value));
			Edwards448.ToCached(in p, out EdwardsCachedPoint cached);
			Edwards448.Add(in p, in cached, out EdwardsCompletedPoint completed);
			Edwards448.ToExtended(in completed, out EdwardsPoint sum);
			Check(failures, $"Add {Show(value)}", sum, Add(value, value));
			Edwards448.Subtract(in p, in cached, out completed);
			Edwards448.ToExtended(in completed, out sum);
			Check(failures, $"Subtract {Show(value)}", sum, Identity);
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task TwistedFormulasMatchTheReference()
	{
		List<string> failures = [];
		Random random = new(4);
		List<EdwardsValue> points = [Identity, TwistedBase, Negate(TwistedBase)];

		for (int i = 0; i < 6; ++i)
		{
			points.Add(TwistedMultiply(TwistedBase, RandomBelow(random, L)));
		}

		TwistedNielsPoint[] niels = new TwistedNielsPoint[points.Count];
		TwistedEdwards448.ToNielsVariableTime([.. points.Select(value => ToPoint(value, 1 + RandomBelow(random, P - 1)))], niels);

		for (int i = 0; i < 2 * points.Count; ++i)
		{
			// The largest tight limbs in Z take AddNiels to the bound of the products.
			EdwardsValue left = points[i % points.Count];
			EdwardsPoint p = i < points.Count ? ToPoint(left, 1 + RandomBelow(random, P - 1)) : ToPoint(left, ValueOf(LargestTight)) with { Z = LargestTight };
			TwistedEdwards448.Double(in Edwards448.AsProjective(in p), out EdwardsCompletedPoint completed);
			Edwards448.ToExtended(in completed, out EdwardsPoint doubled);
			Check(failures, $"Double {Show(left)}", doubled, TwistedAdd(left, left));
			TwistedEdwards448.Untwist(in Edwards448.AsProjective(in p), out completed);
			Edwards448.ToExtended(in completed, out EdwardsPoint untwisted);
			Check(failures, $"Untwist {Show(left)}", untwisted, Untwist(left));
			TwistedEdwards448.FromNiels(in niels[i % points.Count], out EdwardsPoint fromNiels);
			Check(failures, $"FromNiels {Show(left)}", fromNiels, left);

			for (int j = 0; j < points.Count; ++j)
			{
				EdwardsValue right = points[j];
				TwistedEdwards448.AddNiels(in p, in niels[j], out completed);
				Edwards448.ToExtended(in completed, out EdwardsPoint sum);
				Check(failures, $"AddNiels {Show(left)}, {Show(right)}", sum, TwistedAdd(left, right));
				EdwardsPoint q = ToPoint(right, 1 + RandomBelow(random, P - 1));
				TwistedEdwards448.ToCached(in q, out TwistedCachedPoint cached);
				TwistedEdwards448.Add(in p, in cached, out completed);
				Edwards448.ToExtended(in completed, out sum);
				Check(failures, $"Add {Show(left)}, {Show(right)}", sum, TwistedAdd(left, right));
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Entry e of comb j is Σ ε_m·2^(Spacing·(m + Teeth·j))·Base with the top ε 1 and the others 2e_m − 1, in canonical coordinates.
	[Test]
	public async Task BaseTableHoldsTheCombValues()
	{
		const int teeth = TwistedBaseTable.Teeth;
		const int spacing = TwistedBaseTable.Spacing;
		List<string> failures = [];

		foreach (int comb in (int[])[0, 1, TwistedBaseTable.CombCount - 1])
		{
			foreach (int e in (int[])[0, 1, TwistedBaseTable.CombLength - 2, TwistedBaseTable.CombLength - 1])
			{
				BigInteger scalar = BigInteger.One << spacing * (teeth - 1 + teeth * comb);

				for (int m = 0; m < teeth - 1; ++m)
				{
					scalar += (2 * (e >> m & 1) - 1) * (BigInteger.One << spacing * (m + teeth * comb));
				}

				EdwardsValue expected = TwistedMultiply(TwistedBase, (scalar % L + L) % L);
				TwistedBaseTable.Select(comb, (uint)e, 0, out TwistedNielsPoint entry);
				Field448[] coordinates = [entry.YPlusX, entry.YMinusX, entry.TwoDXY];
				BigInteger x = Mod(ValueOf(entry.YPlusX) - ValueOf(entry.YMinusX)) * Inverse(2) % P;
				BigInteger y = Mod(ValueOf(entry.YPlusX) + ValueOf(entry.YMinusX)) * Inverse(2) % P;

				if (!coordinates.All(IsCanonical) || new EdwardsValue(x, y) != expected || Mod(ValueOf(entry.TwoDXY) - 2 * TwistedD * x * y) != 0)
				{
					failures.Add($"comb {comb}, entry {e}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task TorsionHoldsTheFourPointsOfSmallOrder()
	{
		using (Assert.Multiple())
		{
			await Assert.That(Torsion.Distinct().Count()).IsEqualTo(4);
			await Assert.That(Torsion.All(IsOnCurve)).IsTrue();
			await Assert.That(Torsion.All(static point => Multiply(point, 4) == Identity)).IsTrue();
			await Assert.That(Multiply(Torsion[1], 2)).IsNotEqualTo(Identity);
		}
	}

	[Test]
	public async Task EncodingsRoundTrip()
	{
		Random random = new(5);
		List<string> failures = [];
		List<EdwardsValue> points = [.. Torsion, Base];

		for (int i = 0; i < 4 * RandomCount; ++i)
		{
			points.Add(RandomPoint(random));
		}

		foreach (EdwardsValue value in points)
		{
			EdwardsPoint point = ToPoint(value, 1 + RandomBelow(random, P - 1));
			byte[] expected = Encode(value);
			byte[] encoded = new byte[Edwards448.EncodedLength];
			byte[] variableTime = new byte[Edwards448.EncodedLength];
			Edwards448.Encode(in point, encoded);
			Edwards448.EncodeVariableTime(in point, variableTime);
			bool decoded = Edwards448.TryDecode(expected, out EdwardsPoint result);

			if (!encoded.AsSpan().SequenceEqual(expected) || !variableTime.AsSpan().SequenceEqual(expected) || !decoded || ToValue(result) != value)
			{
				failures.Add($"encoding of {Show(value)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// RFC 8032 §5.2.3, strictly, including encodings of the torsion points.
	[Test]
	public async Task DecodingRejectsWhatRfc8032Rejects()
	{
		List<byte[]> invalid = [];

		// p and p + 1 would be y = 0 and 1 of torsion points.
		foreach (BigInteger y in (BigInteger[])[P, P + 1, P + 2, P + (BigInteger.One << 223), (BigInteger.One << 448) - 2, (BigInteger.One << 448) - 1])
		{
			byte[] encoded = EncodeInteger(y, 57);
			invalid.Add(encoded);
			invalid.Add(WithSign(encoded));
		}

		byte[] baseEncoding = Encode(Base);

		for (int bit = 0; bit < 7; ++bit)
		{
			byte[] encoded = (byte[])baseEncoding.Clone();
			encoded[56] |= (byte)(1 << bit);
			invalid.Add(encoded);
		}

		// x = 0 with the sign bit: the identity and the point of order 2.
		invalid.Add(WithSign(EncodeInteger(1, 57)));
		invalid.Add(WithSign(EncodeInteger(P - 1, 57)));

		int nonSquares = 0;

		for (BigInteger y = 2; nonSquares < 8; ++y)
		{
			if (!IsSquare((y * y - 1) * Inverse(D * y * y - 1)))
			{
				invalid.Add(EncodeInteger(y, 57));
				invalid.Add(WithSign(EncodeInteger(y, 57)));
				++nonSquares;
			}
		}

		List<string> failures = [];

		foreach (byte[] encoded in invalid)
		{
			if (Decode(encoded) is not null)
			{
				failures.Add($"the reference decodes {Convert.ToHexString(encoded)}");
			}

			if (Edwards448.TryDecode(encoded, out EdwardsPoint result) || MemoryMarshal.AsBytes(new ReadOnlySpan<EdwardsPoint>(in result)).ContainsAnyExcept((byte)0))
			{
				failures.Add($"TryDecode {Convert.ToHexString(encoded)}");
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(Edwards448.TryDecode(new byte[56], out _)).IsFalse();
			await Assert.That(Edwards448.TryDecode(new byte[58], out _)).IsFalse();
			await Assert.That(Edwards448.TryDecode(Encode(Torsion[1]), out _)).IsTrue();
		}
	}

	[Test]
	public async Task OrderTimesBaseIsTheIdentity()
	{
		Edwards448.MultiplyBase(Scalar(L), out EdwardsPoint product);
		Edwards448.MultiplyBase(Scalar(L + 1), out EdwardsPoint next);

		using (Assert.Multiple())
		{
			await Assert.That(ToValue(product)).IsEqualTo(Identity);
			await Assert.That(ToValue(next)).IsEqualTo(Base);
		}
	}

	[Test]
	public async Task ToMontgomeryUFollowsTheIsogeny()
	{
		Random random = new(6);
		List<string> failures = [];
		List<EdwardsValue> points = [.. Torsion, Base];

		for (int i = 0; i < RandomCount; ++i)
		{
			points.Add(RandomPoint(random));
		}

		foreach (EdwardsValue value in points)
		{
			byte[] u = new byte[56];
			Edwards448.ToMontgomeryU(ToPoint(value, 1 + RandomBelow(random, P - 1)), u);

			if (!u.AsSpan().SequenceEqual(EncodeInteger(ToMontgomeryU(value))))
			{
				failures.Add($"ToMontgomeryU {Show(value)}");
			}
		}

		byte[] baseU = new byte[56];
		Edwards448.ToMontgomeryU(in Edwards448.Base, baseU);

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(DecodeInteger(baseU)).IsEqualTo(new BigInteger(5));
		}
	}

	[Test]
	public async Task PointTableGivesTheSameDoubleProducts()
	{
		Random random = new(7);
		List<string> failures = [];
		List<BigInteger> scalars = [0, 1, L - 1, (BigInteger.One << 448) - 1, RandomBelow(random, L), RandomBelow(random, BigInteger.One << 448)];
		EdwardsValue[] points = [Base, Torsion[1], Add(RandomPoint(random), Torsion[3]), RandomPoint(random)];

		foreach (EdwardsValue value in points)
		{
			EdwardsPoint point = ToPoint(value, 1 + RandomBelow(random, P - 1));
			EdwardsAffinePoint[] table = EdwardsVariableTimePointTable.Build(in point);

			for (int i = 0; i < scalars.Count; ++i)
			{
				BigInteger a = scalars[i];
				BigInteger b = scalars[(i * 5 + 1) % scalars.Count];
				Edwards448.DoubleScalarMultiplyVariableTime(Scalar(a), table, Scalar(b), out EdwardsPoint withTable);
				Edwards448.DoubleScalarMultiplyVariableTime(Scalar(a), in point, Scalar(b), out EdwardsPoint plain);
				EdwardsValue expected = Add(Multiply(value, a), Multiply(Base, b));
				Check(failures, $"with the table, {a:X}·{Show(value)} + {b:X}·B", withTable, expected);
				Check(failures, $"without the table, {a:X}·{Show(value)} + {b:X}·B", plain, expected);
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	private static byte[] WithSign(byte[] encoded)
	{
		byte[] signed = (byte[])encoded.Clone();
		signed[56] |= 0x80;
		return signed;
	}

	private static void Check(List<string> failures, string operation, in EdwardsPoint actual, EdwardsValue expected)
	{
		EdwardsValue? value = ToValue(actual);

		if (value != expected)
		{
			failures.Add($"{operation} gave {Show(value)}, expected {Show(expected)}");
		}
	}
}
