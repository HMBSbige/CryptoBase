using CryptoBase.EllipticCurves.Curve448;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.Curve448.Curve448Reference;
using static CryptoBase.Tests.EllipticCurves.Curve448.Field448TestUtils;

namespace CryptoBase.Tests.EllipticCurves.Curve448;

public class Field448Test
{
	private const int RandomCount = 40;

	// In multiples of 2^56: the largest that xy ≤ 12.25 allows with either side at most 8.
	private static readonly (ulong Left, ulong Right)[] ProductBounds = [(SquareBound, SquareBound), (8UL << 56, (49UL << 56) / 32), (1UL << 58, 3UL << 56), (3UL << 56, 1UL << 58), ((49UL << 56) / 32, 8UL << 56)];

	[Test]
	public async Task ProductsMatchBigIntegerUpToTheirLargestLimbs()
	{
		List<string> failures = [];
		Random random = new(1);

		foreach ((ulong leftBound, ulong rightBound) in ProductBounds)
		{
			List<Field448> lefts = [.. Elements(random, leftBound, RandomCount / 4), .. TightElements(random, 2)];
			List<Field448> rights = [.. Elements(random, rightBound, RandomCount / 4), .. TightElements(random, 2)];

			foreach (Field448 x in lefts)
			{
				foreach (Field448 y in rights)
				{
					Field448.Multiply(in x, in y, out Field448 product);
					Check(failures, $"Multiply {Show(x)}, {Show(y)}", product, ValueOf(x) * ValueOf(y), IsTight);
				}
			}
		}

		foreach (Field448 x in (List<Field448>)[.. Elements(random, SquareBound, RandomCount), .. TightElements(random, 8)])
		{
			Field448.Square(in x, out Field448 square);
			Check(failures, $"Square {Show(x)}", square, ValueOf(x) * ValueOf(x), IsTight);
		}

		foreach (Field448 x in (List<Field448>)[.. Elements(random, 1UL << 58, RandomCount), .. TightElements(random, 8)])
		{
			foreach (uint c in (uint[])[0, 1, 2, 39081, 39082, (1u << 17) - 1])
			{
				Field448.MultiplySmall(in x, c, out Field448 scaled);
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

		foreach (Field448 x in Elements(random, SquareBound, 8))
		{
			foreach (int count in (int[])[1, 2, 5, 50])
			{
				Field448.SquareTimes(in x, count, out Field448 power);
				Check(failures, $"SquareTimes {Show(x)}, {count}", power, BigInteger.ModPow(Mod(ValueOf(x)), BigInteger.One << count, P), IsTight);
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Right operands up to the limbs of 2p for Subtract and Negate, and of 4p for SubtractFromFourP.
	[Test]
	public async Task SumsAndDifferencesMatchBigInteger()
	{
		List<string> failures = [];
		Random random = new(3);
		ulong[] twoP = [(1UL << 57) - 2, (1UL << 57) - 2, (1UL << 57) - 2, (1UL << 57) - 2, (1UL << 57) - 4, (1UL << 57) - 2, (1UL << 57) - 2, (1UL << 57) - 2];
		ulong[] fourP = [(1UL << 58) - 4, (1UL << 58) - 4, (1UL << 58) - 4, (1UL << 58) - 4, (1UL << 58) - 8, (1UL << 58) - 4, (1UL << 58) - 4, (1UL << 58) - 4];
		Field448 largestTwoP = Limbs(twoP);
		Field448 largestFourP = Limbs(fourP);
		List<Field448> lefts = Elements(random, 1UL << 60, RandomCount);
		List<Field448> rights = [.. TightElements(random, RandomCount), largestTwoP];

		foreach (Field448 x in lefts)
		{
			foreach (Field448 y in rights)
			{
				Field448.Add(in x, in y, out Field448 sum);
				Check(failures, $"Add {Show(x)}, {Show(y)}", sum, ValueOf(x) + ValueOf(y), value => IsLimbwise(value, x, y, new ulong[8], 1));
				Field448.Subtract(in x, in y, out Field448 difference);
				Check(failures, $"Subtract {Show(x)}, {Show(y)}", difference, ValueOf(x) - ValueOf(y), value => IsLimbwise(value, x, y, twoP, -1));
			}

			foreach (Field448 y in (Field448[])[.. rights.Take(8), largestFourP])
			{
				Field448.SubtractFromFourP(in x, in y, out Field448 difference);
				Check(failures, $"SubtractFromFourP {Show(x)}, {Show(y)}", difference, ValueOf(x) - ValueOf(y), value => IsLimbwise(value, x, y, fourP, -1));
			}
		}

		foreach (Field448 y in rights)
		{
			Field448.Negate(in y, out Field448 negated);
			Check(failures, $"Negate {Show(y)}", negated, -ValueOf(y), IsTight);
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task CarriesAndReductionsKeepTheValue()
	{
		List<string> failures = [];
		Random random = new(4);
		List<Field448> values = [.. Elements(random, ulong.MaxValue, RandomCount), .. Elements(random, SquareBound, 8), .. TightElements(random, 8)];

		foreach (Field448 x in values)
		{
			BigInteger value = ValueOf(x);
			Field448.Carry(in x, out Field448 carried);
			Check(failures, $"Carry {Show(x)}", carried, value, IsTight);
			Field448.Reduce(in x, out Field448 reduced);
			Check(failures, $"Reduce {Show(x)}", reduced, value, IsCanonical);

			byte[] bytes = new byte[Field448.ByteLength];
			Field448.ToBytes(in x, bytes);
			ulong[] limbs = new ulong[7];
			Field448.ToLimbs(in x, limbs);
			BigInteger fromLimbs = limbs.Select((limb, i) => (BigInteger)limb << 64 * i).Aggregate(BigInteger.Add);

			if (!bytes.AsSpan().SequenceEqual(EncodeInteger(Mod(value))) || fromLimbs != Mod(value))
			{
				failures.Add($"ToBytes or ToLimbs {Show(x)}");
			}

			ulong zero = Mod(value).IsZero ? ulong.MaxValue : 0;
			ulong negative = Mod(value).IsEven ? 0 : ulong.MaxValue;

			if (Field448.IsZero(in x) != zero || Field448.IsNegative(in x) != negative)
			{
				failures.Add($"IsZero or IsNegative {Show(x)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task ZeroTestsReduceFirst()
	{
		List<string> failures = [];
		Field448[] zeros = [Element(0), Split(P), Limbs([(1UL << 57) - 2, (1UL << 57) - 2, (1UL << 57) - 2, (1UL << 57) - 2, (1UL << 57) - 4, (1UL << 57) - 2, (1UL << 57) - 2, (1UL << 57) - 2])];
		Field448 one = Element(1);

		foreach (Field448 zero in zeros)
		{
			Field448 above = zero;
			++above.L0;
			Field448 below = zero;
			below.L0 = zero.L0 is 0 ? (1UL << 56) - 1 : zero.L0 - 1;

			if (Field448.IsZero(in zero) is not ulong.MaxValue || Field448.AreEqual(in zero, in zeros[0]) is not ulong.MaxValue)
			{
				failures.Add($"IsZero or AreEqual {Show(zero)}");
			}

			if (Field448.IsZero(in above) is not 0 || Field448.AreEqual(in above, in one) is not ulong.MaxValue || Field448.IsZero(in below) is not 0)
			{
				failures.Add($"IsZero or AreEqual beside {Show(zero)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// All 448 bits count, and values from p up stay unreduced.
	[Test]
	[Arguments("0")]
	[Arguments("1")]
	[Arguments("726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365438")]
	[Arguments("726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439")]
	[Arguments("726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365440")]
	[Arguments("726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365441")]
	[Arguments("726838724295606890549323807888004534353641360687318060281490199180625808140064348006293717206220055745425703034054907647294049823490048")]
	[Arguments("726838724295606890549323807888004534353641360687318060281490199180639288113397923326191050713763565560762521606266177933534601628614655")]
	[Arguments("12345678901234567890123456789012345678901234567890")]
	public async Task DecodingKeepsAllBitsAndTheValue(string decimalValue)
	{
		BigInteger value = BigInteger.Parse(decimalValue);
		byte[] encoded = EncodeInteger(value);
		Field448.FromBytes(encoded, out Field448 x);
		byte[] reencoded = new byte[Field448.ByteLength];
		Field448.ToBytes(in x, reencoded);
		ulong below = value < P ? ulong.MaxValue : 0;

		using (Assert.Multiple())
		{
			await Assert.That(ValueOf(x)).IsEqualTo(value);
			await Assert.That(IsBelow(x, 1UL << 56)).IsTrue();
			await Assert.That(Field448.IsBelowModulus(in x)).IsEqualTo(below);
			await Assert.That(reencoded).IsEquivalentTo(EncodeInteger(Mod(value)), CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task InversionsAndPowersMatchBigInteger()
	{
		List<string> failures = [];
		Random random = new(5);
		List<Field448> values = [.. TightElements(random, 12), .. Elements(random, SquareBound, 6)];

		foreach (Field448 x in values)
		{
			BigInteger value = Mod(ValueOf(x));
			BigInteger inverse = BigInteger.ModPow(value, P - 2, P);
			Field448.Invert(in x, out Field448 result);
			Check(failures, $"Invert {Show(x)}", result, inverse, IsTight);
			Field448.PowerP34(in x, out result);
			Check(failures, $"PowerP34 {Show(x)}", result, BigInteger.ModPow(value, (P - 3) / 4, P), IsTight);
			Field448.InvertVariableTime(in x, out result);
			Check(failures, $"InvertVariableTime {Show(x)}", result, inverse, IsTight);
		}

		await Assert.That(failures).IsEmpty();
	}

	// v = 0 has a root only for u = 0.
	[Test]
	public async Task SquareRootsOfRatiosMatchBigInteger()
	{
		List<string> failures = [];
		Random random = new(6);
		List<(BigInteger U, BigInteger V)> pairs = [(0, 1), (0, 5), (0, 0), (5, 0), (1, 1), (P - 1, 1), (2, 1), (1, 2), (4, 1), (P - 4, 1)];

		for (int i = 0; i < 2 * RandomCount; ++i)
		{
			pairs.Add((RandomBelow(random, P), 1 + RandomBelow(random, P - 1)));
		}

		int squares = 0;

		foreach ((BigInteger u, BigInteger v) in pairs)
		{
			Field448 uElement = Element(u);
			ulong valid = Field448.SqrtRatio(in uElement, Element(v), out Field448 root);
			BigInteger r = ValueOf(root);
			bool square = v.IsZero ? u.IsZero : IsSquare(u * Inverse(v));
			squares += square ? 1 : 0;

			if (valid != (square ? ulong.MaxValue : 0) || !IsTight(root) || square && !Mod(v * r * r - u).IsZero)
			{
				failures.Add($"SqrtRatio {u:X}, {v:X} gave {valid:X} and {r:X}");
			}

			Field448 overU = uElement;
			ulong validOverU = Field448.SqrtRatio(in overU, Element(v), out overU);
			Field448 overV = Element(v);
			ulong validOverV = Field448.SqrtRatio(in uElement, in overV, out overV);

			if (validOverU != valid || validOverV != valid || ValueOf(overU) != r || ValueOf(overV) != r)
			{
				failures.Add($"SqrtRatio {u:X}, {v:X} with the result over u or v gave {validOverU:X} and {validOverV:X}");
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(squares).IsGreaterThan(pairs.Count / 4).And.IsLessThan(pairs.Count * 3 / 4);
		}
	}

	[Test]
	public async Task MasksSelectSwapAndNegate()
	{
		Random random = new(7);
		List<Field448> values = TightElements(random, 8);
		List<string> failures = [];

		for (int i = 0; i + 1 < values.Count; ++i)
		{
			Field448 x = values[i];
			Field448 y = values[i + 1];

			foreach (ulong mask in (ulong[])[0, ulong.MaxValue])
			{
				Field448.ConditionalSelect(mask, in x, in y, out Field448 selected);
				Field448 left = x;
				Field448 right = y;
				Field448.ConditionalSwap(mask, ref left, ref right);
				Field448 negated = x;
				Field448.ConditionalNegate(mask, ref negated);
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
		await Assert.That(ValueOf(Field448.One)).IsEqualTo(BigInteger.One);
	}

	private static void Check(List<string> failures, string operation, in Field448 actual, BigInteger expected, Func<Field448, bool> inForm)
	{
		if (Mod(ValueOf(actual)) != Mod(expected) || !inForm(actual))
		{
			failures.Add($"{operation} gave {Show(actual)}, expected {Mod(expected):X}");
		}
	}

	// Limb by limb, which rules out carries and negative limbs.
	private static bool IsLimbwise(Field448 value, Field448 x, Field448 y, ulong[] multiple, int sign)
	{
		ulong[] a = LimbsOf(x);
		ulong[] b = LimbsOf(y);
		ulong[] r = LimbsOf(value);

		for (int i = 0; i < 8; ++i)
		{
			BigInteger expected = a[i] + (BigInteger)multiple[i] + sign * (BigInteger)b[i];

			if (expected.Sign < 0 || r[i] != expected)
			{
				return false;
			}
		}

		return true;
	}

	private static bool SameLimbs(Field448 left, Field448 right)
	{
		return LimbsOf(left).AsSpan().SequenceEqual(LimbsOf(right));
	}
}
