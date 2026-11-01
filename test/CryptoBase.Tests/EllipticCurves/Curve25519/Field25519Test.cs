using CryptoBase.EllipticCurves.Curve25519;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.Curve25519.Curve25519Reference;
using static CryptoBase.Tests.EllipticCurves.Curve25519.Field25519TestUtils;

namespace CryptoBase.Tests.EllipticCurves.Curve25519;

// Field25519 against BigInteger, with inputs anywhere in the ranges that its members take: limbs up to 2^54 for the products and up to 2^64 for the carries, as well as tight and canonical ones. Every result must also be in the form that its member gives.
public class Field25519Test
{
	private const int RandomCount = 48;

	[Test]
	public async Task ProductsMatchBigIntegerUpToTheirLargestLimbs()
	{
		List<string> failures = [];
		Random random = new(1);
		List<Field25519> values = [.. Elements(random, MultiplyBound, RandomCount), .. TightElements(random, 8)];

		foreach (Field25519 x in values)
		{
			foreach (Field25519 y in values)
			{
				Field25519.Multiply(in x, in y, out Field25519 product);
				Check(failures, $"Multiply {Show(x)}, {Show(y)}", product, ValueOf(x) * ValueOf(y), IsTight);
			}

			Field25519.Square(in x, out Field25519 square);
			Check(failures, $"Square {Show(x)}", square, ValueOf(x) * ValueOf(x), IsTight);

			foreach (uint c in (uint[])[0, 1, 2, 121665, 121666, (1u << 17) - 1])
			{
				Field25519.MultiplySmall(in x, c, out Field25519 scaled);
				Check(failures, $"MultiplySmall {Show(x)}, {c}", scaled, ValueOf(x) * c, IsTight);
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task SquareTimesRepeatsTheSquare()
	{
		List<string> failures = [];
		Random random = new(2);

		foreach (Field25519 x in Elements(random, MultiplyBound, 8))
		{
			foreach (int count in (int[])[1, 2, 5, 50])
			{
				Field25519.SquareTimes(in x, count, out Field25519 power);
				Check(failures, $"SquareTimes {Show(x)}, {count}", power, BigInteger.ModPow(Mod(ValueOf(x)), BigInteger.One << count, P), IsTight);
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Subtract takes a right operand with limbs at most those of 2p, SubtractFromFourP one with limbs at most those of 4p and Negate one like Subtract; the left operands here stay below 2^54 after the differences.
	[Test]
	public async Task SumsAndDifferencesMatchBigInteger()
	{
		List<string> failures = [];
		Random random = new(3);
		ulong[] twoP = [(1UL << 52) - 38, (1UL << 52) - 2, (1UL << 52) - 2, (1UL << 52) - 2, (1UL << 52) - 2];
		ulong[] fourP = [(1UL << 53) - 76, (1UL << 53) - 4, (1UL << 53) - 4, (1UL << 53) - 4, (1UL << 53) - 4];
		Field25519 largestTwoP = Limbs(twoP[0], twoP[1], twoP[2], twoP[3], twoP[4]);
		Field25519 largestFourP = Limbs(fourP[0], fourP[1], fourP[2], fourP[3], fourP[4]);
		List<Field25519> lefts = Elements(random, 1UL << 53, RandomCount);
		List<Field25519> rights = [.. TightElements(random, RandomCount), largestTwoP];

		foreach (Field25519 x in lefts)
		{
			foreach (Field25519 y in rights)
			{
				Field25519.Add(in x, in y, out Field25519 sum);
				Check(failures, $"Add {Show(x)}, {Show(y)}", sum, ValueOf(x) + ValueOf(y), value => IsLimbwise(value, x, y, [0, 0, 0, 0, 0], 1));
				Field25519.Subtract(in x, in y, out Field25519 difference);
				Check(failures, $"Subtract {Show(x)}, {Show(y)}", difference, ValueOf(x) - ValueOf(y), value => IsLimbwise(value, x, y, twoP, -1));
			}

			foreach (Field25519 y in (Field25519[])[.. rights.Take(8), largestFourP])
			{
				Field25519.SubtractFromFourP(in x, in y, out Field25519 difference);
				Check(failures, $"SubtractFromFourP {Show(x)}, {Show(y)}", difference, ValueOf(x) - ValueOf(y), value => IsLimbwise(value, x, y, fourP, -1));
			}
		}

		foreach (Field25519 y in rights)
		{
			Field25519.Negate(in y, out Field25519 negated);
			Check(failures, $"Negate {Show(y)}", negated, -ValueOf(y), IsTight);
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task CarriesAndReductionsKeepTheValue()
	{
		List<string> failures = [];
		Random random = new(4);
		List<Field25519> values = [.. Elements(random, ulong.MaxValue, RandomCount), .. Elements(random, MultiplyBound, 8), .. TightElements(random, 8)];

		foreach (Field25519 x in values)
		{
			BigInteger value = ValueOf(x);
			Field25519.Carry(in x, out Field25519 carried);
			Check(failures, $"Carry {Show(x)}", carried, value, IsTight);
			Field25519.Reduce(in x, out Field25519 reduced);
			Check(failures, $"Reduce {Show(x)}", reduced, value, IsCanonical);

			byte[] bytes = new byte[Field25519.ByteLength];
			Field25519.ToBytes(in x, bytes);
			ulong[] limbs = new ulong[4];
			Field25519.ToLimbs(in x, limbs);

			if (!bytes.AsSpan().SequenceEqual(EncodeInteger(Mod(value))) || limbs[0] + ((BigInteger)limbs[1] << 64) + ((BigInteger)limbs[2] << 128) + ((BigInteger)limbs[3] << 192) != Mod(value))
			{
				failures.Add($"ToBytes or ToLimbs {Show(x)}");
			}

			ulong zero = Mod(value).IsZero ? ulong.MaxValue : 0;
			ulong negative = Mod(value).IsEven ? 0 : ulong.MaxValue;

			if (Field25519.IsZero(in x) != zero || Field25519.IsNegative(in x) != negative)
			{
				failures.Add($"IsZero or IsNegative {Show(x)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// 0, p and 2p are 0, and their neighbours are not.
	[Test]
	public async Task ZeroTestsReduceFirst()
	{
		List<string> failures = [];
		ulong mask = (1UL << 51) - 1;
		Field25519[] zeros = [Limbs(0, 0, 0, 0, 0), Limbs(mask - 18, mask, mask, mask, mask), Limbs((1UL << 52) - 38, (1UL << 52) - 2, (1UL << 52) - 2, (1UL << 52) - 2, (1UL << 52) - 2)];
		Field25519 one = Element(1);

		foreach (Field25519 zero in zeros)
		{
			Field25519 above = zero;
			++above.L0;
			Field25519 below = zero;
			below.L0 = zero.L0 is 0 ? (1UL << 51) - 20 : zero.L0 - 1;

			if (Field25519.IsZero(in zero) is not ulong.MaxValue || Field25519.AreEqual(in zero, in zeros[0]) is not ulong.MaxValue)
			{
				failures.Add($"IsZero or AreEqual {Show(zero)}");
			}

			if (Field25519.IsZero(in above) is not 0 || Field25519.AreEqual(in above, in one) is not ulong.MaxValue || Field25519.IsZero(in below) is not 0)
			{
				failures.Add($"IsZero or AreEqual beside {Show(zero)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Bit 255 is ignored, and values from p to 2^255 − 1 are kept until a reduction; only those fail IsBelowModulus.
	[Test]
	[Arguments("0")]
	[Arguments("1")]
	[Arguments("57896044618658097711785492504343953926634992332820282019728792003956564819948")]
	[Arguments("57896044618658097711785492504343953926634992332820282019728792003956564819949")]
	[Arguments("57896044618658097711785492504343953926634992332820282019728792003956564819950")]
	[Arguments("57896044618658097711785492504343953926634992332820282019728792003956564819967")]
	[Arguments("12345678901234567890123456789012345678901234567890")]
	public async Task DecodingMasksBit255AndKeepsTheValue(string decimalValue)
	{
		BigInteger value = BigInteger.Parse(decimalValue);
		byte[] encoded = EncodeInteger(value);
		byte[] withTopBit = (byte[])encoded.Clone();
		withTopBit[31] |= 0x80;
		List<string> failures = [];

		foreach (byte[] bytes in (byte[][])[encoded, withTopBit])
		{
			Field25519.FromBytes(bytes, out Field25519 x);
			byte[] reencoded = new byte[Field25519.ByteLength];
			Field25519.ToBytes(in x, reencoded);
			ulong below = value < P ? ulong.MaxValue : 0;

			if (ValueOf(x) != value || !IsBelow(x, 1UL << 51) || Field25519.IsBelowModulus(in x) != below || !reencoded.AsSpan().SequenceEqual(EncodeInteger(Mod(value))))
			{
				failures.Add($"FromBytes {Convert.ToHexString(bytes)} gave {Show(x)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task InversionsAndPowersMatchBigInteger()
	{
		List<string> failures = [];
		Random random = new(5);
		List<Field25519> values = [.. TightElements(random, 16), .. Elements(random, MultiplyBound, 8)];

		foreach (Field25519 x in values)
		{
			BigInteger value = Mod(ValueOf(x));
			BigInteger inverse = BigInteger.ModPow(value, P - 2, P);
			Field25519.Invert(in x, out Field25519 result);
			Check(failures, $"Invert {Show(x)}", result, inverse, IsTight);
			Field25519.PowerP58(in x, out result);
			Check(failures, $"PowerP58 {Show(x)}", result, BigInteger.ModPow(value, (P - 5) / 8, P), IsTight);

			// The variable-time inversion reduces first, so any input of the products works for it too.
			Field25519.InvertVariableTime(in x, out result);
			Check(failures, $"InvertVariableTime {Show(x)}", result, inverse, IsTight);
		}

		await Assert.That(failures).IsEmpty();
	}

	// A root is returned for squares, including where v·r² = −u first, and none for non-squares; u = 0 gives the root 0, and v = 0 has a root only for u = 0.
	[Test]
	public async Task SquareRootsOfRatiosMatchBigInteger()
	{
		List<string> failures = [];
		Random random = new(6);
		List<(BigInteger U, BigInteger V)> pairs = [(0, 1), (0, 5), (0, 0), (5, 0), (1, 1), (P - 1, 1), (2, 1), (1, 2), (4, 1), (P - 4, 1)];

		for (int i = 0; i < 4 * RandomCount; ++i)
		{
			pairs.Add((RandomBelow(random, P), 1 + RandomBelow(random, P - 1)));
		}

		int squares = 0;
		int rotated = 0;

		foreach ((BigInteger u, BigInteger v) in pairs)
		{
			Field25519 uElement = Element(u);
			ulong valid = Field25519.SqrtRatio(in uElement, Element(v), out Field25519 root);
			BigInteger r = ValueOf(root);
			BigInteger ratio = Mod(u * Inverse(v));
			BigInteger first = BigInteger.ModPow(ratio, (P + 3) / 8, P);
			bool square = v.IsZero ? u.IsZero : IsSquare(ratio);
			squares += square ? 1 : 0;
			rotated += square && Mod(v * first * first + u).IsZero && !u.IsZero ? 1 : 0;

			if (valid != (square ? ulong.MaxValue : 0) || !IsTight(root) || square && !Mod(v * r * r - u).IsZero)
			{
				failures.Add($"SqrtRatio {u:X}, {v:X} gave {valid:X} and {r:X}");
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(squares).IsGreaterThan(pairs.Count / 4).And.IsLessThan(pairs.Count * 3 / 4);
			await Assert.That(rotated).IsPositive();
		}
	}

	[Test]
	public async Task MasksSelectSwapAndNegate()
	{
		Random random = new(7);
		List<Field25519> values = TightElements(random, 8);
		List<string> failures = [];

		for (int i = 0; i + 1 < values.Count; ++i)
		{
			Field25519 x = values[i];
			Field25519 y = values[i + 1];

			foreach (ulong mask in (ulong[])[0, ulong.MaxValue])
			{
				Field25519.ConditionalSelect(mask, in x, in y, out Field25519 selected);
				Field25519 left = x;
				Field25519 right = y;
				Field25519.ConditionalSwap(mask, ref left, ref right);
				Field25519 negated = x;
				Field25519.ConditionalNegate(mask, ref negated);
				bool set = mask is not 0;

				if (!SameLimbs(selected, set ? x : y) || !SameLimbs(left, set ? y : x) || !SameLimbs(right, set ? x : y) || !IsTight(negated) || Mod(ValueOf(negated)) != Mod(set ? -ValueOf(x) : ValueOf(x)))
				{
					failures.Add($"masks {mask:X} on {Show(x)}, {Show(y)}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task ConstantsMatchTheirDefinitions()
	{
		using (Assert.Multiple())
		{
			await Assert.That(ValueOf(Field25519.One)).IsEqualTo(BigInteger.One);
			await Assert.That(ValueOf(Field25519.SqrtMinusOne)).IsEqualTo(SqrtMinusOne);
			await Assert.That(Mod(SqrtMinusOne * SqrtMinusOne)).IsEqualTo(P - 1);
			await Assert.That(ValueOf(Edwards25519.D)).IsEqualTo(D);
			await Assert.That(ValueOf(Edwards25519.TwoD)).IsEqualTo(Mod(2 * D));
		}
	}

	private static void Check(List<string> failures, string operation, in Field25519 actual, BigInteger expected, Func<Field25519, bool> inForm)
	{
		if (Mod(ValueOf(actual)) != Mod(expected) || !inForm(actual))
		{
			failures.Add($"{operation} gave {Show(actual)}, expected {Mod(expected):X}");
		}
	}

	// Each limb of value is x_i + multiple_i + sign·y_i, which rules out carries and negative limbs.
	private static bool IsLimbwise(Field25519 value, Field25519 x, Field25519 y, ulong[] multiple, int sign)
	{
		ulong[] a = [x.L0, x.L1, x.L2, x.L3, x.L4];
		ulong[] b = [y.L0, y.L1, y.L2, y.L3, y.L4];
		ulong[] r = [value.L0, value.L1, value.L2, value.L3, value.L4];

		for (int i = 0; i < 5; ++i)
		{
			BigInteger expected = a[i] + (BigInteger)multiple[i] + sign * (BigInteger)b[i];

			if (expected.Sign < 0 || r[i] != expected)
			{
				return false;
			}
		}

		return true;
	}

	private static bool SameLimbs(Field25519 left, Field25519 right)
	{
		return (left.L0, left.L1, left.L2, left.L3, left.L4) == (right.L0, right.L1, right.L2, right.L3, right.L4);
	}
}
