using CryptoBase.EllipticCurves.Curve25519;
using System.Numerics;
using System.Runtime.InteropServices;
using static CryptoBase.Tests.EllipticCurves.Curve25519.Curve25519Reference;
using static CryptoBase.Tests.EllipticCurves.Curve25519.Curve25519TestUtils;

namespace CryptoBase.Tests.EllipticCurves.Curve25519;

// Edwards25519 against Curve25519Reference. Points of every order go in, with Z other than 1, since the formulas are complete and the torsion points are where incomplete ones fail.
public class Edwards25519Test
{
	private const int RandomCount = 12;

	private static readonly EdwardsValue[] Torsion = TorsionPoints();

	[Test]
	public async Task BaseIsThePointOfRfc8032()
	{
		byte[] encoded = new byte[Edwards25519.EncodedLength];
		Edwards25519.Encode(in Edwards25519.Base, encoded);

		using (Assert.Multiple())
		{
			await Assert.That(ToValue(Edwards25519.Base)).IsEqualTo(Base);
			await Assert.That(Base.X).IsEqualTo(BigInteger.Parse("15112221349535400772501151409588531511454012693041857206046113283949847762202"));
			await Assert.That(IsOnCurve(Base)).IsTrue();
			await Assert.That(Convert.ToHexStringLower(encoded)).IsEqualTo("5866666666666666666666666666666666666666666666666666666666666666");
		}
	}

	[Test]
	public async Task GroupLawMatchesTheReference()
	{
		List<string> failures = [];
		Random random = new(1);
		List<EdwardsValue> points = [.. Torsion, Base, Negate(Base), Add(Base, Torsion[1])];

		for (int i = 0; i < RandomCount; ++i)
		{
			points.Add(RandomPoint(random));
		}

		foreach (EdwardsValue left in points)
		{
			EdwardsPoint p = ToPoint(left, 1 + RandomBelow(random, P - 1));
			Edwards25519.Double(in p, out EdwardsPoint doubled);
			Edwards25519.Negate(in p, out EdwardsPoint negated);
			Check(failures, $"Double {Show(left)}", doubled, Add(left, left));
			Check(failures, $"Negate {Show(left)}", negated, Negate(left));

			foreach (EdwardsValue right in points)
			{
				EdwardsPoint q = ToPoint(right, 1 + RandomBelow(random, P - 1));
				Edwards25519.ToCached(in q, out EdwardsCachedPoint cached);
				Edwards25519.Add(in p, in cached, out EdwardsCompletedPoint completed);
				Edwards25519.ToExtended(in completed, out EdwardsPoint sum);
				Edwards25519.Subtract(in p, in cached, out completed);
				Edwards25519.ToExtended(in completed, out EdwardsPoint difference);
				Check(failures, $"Add {Show(left)}, {Show(right)}", sum, Add(left, right));
				Check(failures, $"Subtract {Show(left)}, {Show(right)}", difference, Add(left, Negate(right)));

				EdwardsNielsPoint[] niels = new EdwardsNielsPoint[1];
				Edwards25519.ToNielsVariableTime([q], niels);
				Edwards25519.AddNiels(in p, in niels[0], out completed);
				Edwards25519.ToExtended(in completed, out sum);
				Edwards25519.SubtractNiels(in p, in niels[0], out completed);
				Edwards25519.ToExtended(in completed, out difference);
				Check(failures, $"AddNiels {Show(left)}, {Show(right)}", sum, Add(left, right));
				Check(failures, $"SubtractNiels {Show(left)}, {Show(right)}", difference, Add(left, Negate(right)));
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task TorsionHoldsTheEightPointsOfSmallOrder()
	{
		using (Assert.Multiple())
		{
			await Assert.That(Torsion.Distinct().Count()).IsEqualTo(8);
			await Assert.That(Torsion).All(static point => Multiply(point, 8) == Identity);
		}
	}

	[Test]
	public async Task EncodingsRoundTrip()
	{
		Random random = new(3);
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
			byte[] encoded = new byte[Edwards25519.EncodedLength];
			byte[] variableTime = new byte[Edwards25519.EncodedLength];
			Edwards25519.Encode(in point, encoded);
			Edwards25519.EncodeVariableTime(in point, variableTime);
			bool decoded = Edwards25519.TryDecode(expected, out EdwardsPoint result);

			if (!encoded.AsSpan().SequenceEqual(expected) || !variableTime.AsSpan().SequenceEqual(expected) || !decoded || ToValue(result) != value)
			{
				failures.Add($"encoding of {Show(value)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// RFC 8032 §5.1.3 strictly: y of p or more, x = 0 with the sign bit set and y without an x all fail, including where they encode the torsion points.
	[Test]
	public async Task DecodingRejectsWhatRfc8032Rejects()
	{
		List<byte[]> invalid = [];

		// y from p to 2^255 − 1, with either sign; p and p + 1 would be y = 0 and y = 1 of torsion points.
		for (BigInteger y = P; y < BigInteger.One << 255; ++y)
		{
			byte[] encoded = EncodeInteger(y);
			invalid.Add(encoded);
			invalid.Add(WithSign(encoded));
		}

		// x = 0 with the sign bit: the identity and the point of order 2.
		invalid.Add(WithSign(EncodeInteger(1)));
		invalid.Add(WithSign(EncodeInteger(P - 1)));

		// The first y without an x, and some more.
		int nonSquares = 0;

		for (BigInteger y = 2; nonSquares < 8; ++y)
		{
			if (!IsSquare((y * y - 1) * Inverse(D * y * y + 1)))
			{
				invalid.Add(EncodeInteger(y));
				invalid.Add(WithSign(EncodeInteger(y)));
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

			if (Edwards25519.TryDecode(encoded, out EdwardsPoint result) || MemoryMarshal.AsBytes(new ReadOnlySpan<EdwardsPoint>(in result)).ContainsAnyExcept((byte)0))
			{
				failures.Add($"TryDecode {Convert.ToHexString(encoded)}");
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(Edwards25519.TryDecode(new byte[31], out _)).IsFalse();
			await Assert.That(Edwards25519.TryDecode(new byte[33], out _)).IsFalse();
		}
	}

	[Test]
	public async Task OrderTimesBaseIsTheIdentity()
	{
		Edwards25519.MultiplyBase(Scalar(L), out EdwardsPoint product);
		Edwards25519.MultiplyBase(Scalar(L + 1), out EdwardsPoint next);

		using (Assert.Multiple())
		{
			await Assert.That(ToValue(product)).IsEqualTo(Identity);
			await Assert.That(ToValue(next)).IsEqualTo(Base);
			await Assert.That(Multiply(Base, L)).IsEqualTo(Identity);
		}
	}

	[Test]
	public async Task ToMontgomeryUFollowsTheBirationalMap()
	{
		Random random = new(4);
		List<string> failures = [];
		List<EdwardsValue> points = [.. Torsion, Base];

		for (int i = 0; i < RandomCount; ++i)
		{
			points.Add(RandomPoint(random));
		}

		foreach (EdwardsValue value in points)
		{
			byte[] u = new byte[32];
			Edwards25519.ToMontgomeryU(ToPoint(value, 1 + RandomBelow(random, P - 1)), u);

			if (!u.AsSpan().SequenceEqual(EncodeInteger(ToMontgomeryU(value))))
			{
				failures.Add($"ToMontgomeryU {Show(value)}");
			}
		}

		byte[] baseU = new byte[32];
		Edwards25519.ToMontgomeryU(in Edwards25519.Base, baseU);

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(DecodeInteger(baseU)).IsEqualTo(new BigInteger(9));
		}
	}

	// The table takes the doublings of 16-bit parts and the fixed-base windows; it must agree with the plain multiplication and the reference.
	[Test]
	public async Task PointTableGivesTheSameDoubleProducts()
	{
		Random random = new(5);
		List<string> failures = [];
		List<BigInteger> scalars = Scalars(random, 2);
		EdwardsValue[] points = [Base, Torsion[3], Add(RandomPoint(random), Torsion[1]), RandomPoint(random)];

		foreach (EdwardsValue value in points)
		{
			EdwardsPoint point = ToPoint(value, 1 + RandomBelow(random, P - 1));
			EdwardsNielsPoint[] table = EdwardsVariableTimePointTable.Build(in point);

			for (int i = 0; i < scalars.Count; ++i)
			{
				BigInteger a = scalars[i];
				BigInteger b = scalars[(i * 7 + 3) % scalars.Count];
				Edwards25519.DoubleScalarMultiplyVariableTime(Scalar(a), table, Scalar(b), out EdwardsPoint withTable);
				Edwards25519.DoubleScalarMultiplyVariableTime(Scalar(a), in point, Scalar(b), out EdwardsPoint plain);
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
		signed[31] |= 0x80;
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
