using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.EcTestUtils;

namespace CryptoBase.Tests.EllipticCurves;

public class EcVariableTimeGroupTest
{
	private const int RandomCount = 8;

	// The one-off u1·G + u2·Q takes Q, 3Q, …, 15Q for the NAF of width 5.
	private const int OddMultipleCount = 8;

	// The affine right input cannot be the point at infinity.
	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task MixedAddMatchesTheReference(CurveCase curve)
	{
		EcReference reference = curve.Reference;
		Random random = new(12);
		List<string> failures = [];

		foreach ((CurvePoint? left, CurvePoint? right) in EcGroupTest.Pairs(reference, random))
		{
			if (right is null)
			{
				continue;
			}

			JacobianValue sum = curve.AddVariableTime(reference.RandomizeJacobian(left, random), right);
			CheckPoint(failures, reference, $"{Show(left)} + affine {Show(right)}", sum, reference.Add(left, right));
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task ResultMayOverwriteTheLeftInput(CurveCase curve)
	{
		EcReference reference = curve.Reference;
		Random random = new(14);
		List<string> failures = [];

		for (int i = 0; i < RandomCount; ++i)
		{
			CurvePoint point = reference.RandomPoint(random);
			CurvePoint? other = (i % 3) switch
			{
				0 => point,
				1 => reference.Negate(point),
				_ => reference.RandomPoint(random)
			};

			JacobianValue left = reference.RandomizeJacobian(point, random);
			CurvePoint affine = other ?? point;
			CheckSame(failures, "mixed Add in place", curve.AddVariableTime(left, affine, true), curve.AddVariableTime(left, affine));
		}

		await Assert.That(failures).IsEmpty();
	}

	private static readonly int[] Widths = [2, 3, 4, 5, 6, 7, 8];

	public enum PointKind
	{
		Generator,
		NegatedGenerator,
		Random,
		MultipleOfGenerator
	}

	// A test of its own for each, so that the larger curves run in parallel.
	[Test]
	[MatrixDataSource]
	public async Task MultiplyAddMatchesTheReference([MatrixMethod<CurveCase>(nameof(CurveCase.All))] CurveCase curve, [Matrix] PointKind kind)
	{
		EcReference reference = curve.Reference;
		BigInteger n = curve.Order;
		Random random = new(1 + (int)kind);
		BigInteger d = 1 + EcReference.RandomBelow(random, n - 1);

		CurvePoint point = kind switch
		{
			PointKind.Generator => reference.Generator,
			PointKind.NegatedGenerator => reference.PublicKey(n - 1),
			PointKind.Random => reference.RandomPoint(random),
			_ => reference.PublicKey(d)
		};

		BigInteger[] scalars = EdgeScalars(curve);
		List<(BigInteger U1, BigInteger U2)> pairs = [.. scalars.SelectMany(_ => scalars, static (u1, u2) => (u1, u2))];

		for (int i = 0; i < RandomCount; ++i)
		{
			pairs.Add((EcReference.RandomBelow(random, n), EcReference.RandomBelow(random, n)));
		}

		CurvePoint?[] sums = reference.Add(reference.Multiply(reference.Generator, [.. pairs.Select(static pair => pair.U1)]), reference.Multiply(point, [.. pairs.Select(static pair => pair.U2)]));
		List<string> failures = [];

		foreach (((BigInteger u1, BigInteger u2), CurvePoint? sum) in pairs.Zip(sums))
		{
			Check(failures, curve, u1, point, u2, sum);
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MatrixDataSource]
	public async Task OddMultiplesHoldEachOddMultiple([MatrixMethod<CurveCase>(nameof(CurveCase.All))] CurveCase curve, [Matrix] PointKind kind)
	{
		EcReference reference = curve.Reference;
		BigInteger n = curve.Order;
		Random random = new(17 + (int)kind);

		CurvePoint point = kind switch
		{
			PointKind.Generator => reference.Generator,
			PointKind.NegatedGenerator => reference.PublicKey(n - 1),
			PointKind.Random => reference.RandomPoint(random),
			_ => reference.PublicKey(1 + EcReference.RandomBelow(random, n - 1))
		};

		CurvePoint[] multiples = curve.OddMultiplesVariableTime(point, OddMultipleCount);
		CurvePoint?[] expected = reference.Multiply(point, [.. Enumerable.Range(0, OddMultipleCount).Select(static j => (BigInteger)(2 * j + 1))]);

		using (Assert.Multiple())
		{
			await Assert.That(multiples.Length).IsEqualTo(expected.Length);
			await Assert.That(Enumerable.Range(0, Math.Min(multiples.Length, expected.Length)).Where(i => multiples[i] != expected[i])).IsEmpty();
		}
	}

	// The digits of u1 add multiples of G before those of u2 add multiples of Q at the same position. With Q = ±G, u1 = u2 = 1 adds G and ±G at the last digit, and u1 = u2 = 2^(N − 1) + 1 does so at the top digit too, where −G leaves the point at infinity for the doublings and the additions below. With Q = ±2⁻¹·G, u2 = 2 leaves ±G for G at the last digit.
	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task MultiplyAddMeetsEqualAndOppositePoints(CurveCase curve)
	{
		EcReference reference = curve.Reference;
		BigInteger n = curve.Order;
		BigInteger split = (BigInteger.One << curve.ScalarBitLength - 1) + 1;
		CurvePoint generator = reference.Generator;
		CurvePoint negated = reference.PublicKey(n - 1);
		CurvePoint half = reference.PublicKey((n + 1) / 2);
		CurvePoint negatedHalf = reference.PublicKey((n - 1) / 2);
		CurvePoint? twice = reference.Add(generator, generator);
		List<string> failures = [];

		Check(failures, curve, 1, generator, 1, twice);
		Check(failures, curve, 1, negated, 1, null);
		Check(failures, curve, split, generator, split, reference.Multiply(generator, 2 * split % n));
		Check(failures, curve, split, negated, split, null);
		Check(failures, curve, 1, half, 2, twice);
		Check(failures, curve, 1, negatedHalf, 2, null);

		await Assert.That(failures).IsEmpty();
	}

	// Q = d·G with u1 = −u2·d, the sum ECDSA rejects, and u1 = u2·d, which adds a point to itself.
	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task MultiplyAddCancelsAndDoubles(CurveCase curve)
	{
		EcReference reference = curve.Reference;
		BigInteger n = curve.Order;
		Random random = new(5);
		List<string> failures = [];

		for (int i = 0; i < RandomCount; ++i)
		{
			BigInteger d = 1 + EcReference.RandomBelow(random, n - 1);
			BigInteger u2 = i is 0 ? 1 : 1 + EcReference.RandomBelow(random, n - 1);
			CurvePoint point = reference.PublicKey(d);
			BigInteger u1 = u2 * d % n;
			Check(failures, curve, n - u1, point, u2, null);
			Check(failures, curve, u1, point, u2, reference.Multiply(reference.Generator, 2 * u1 % n));
		}

		await Assert.That(failures).IsEmpty();
	}

	// After the parts of u2, the table path adds the windows of u1 to u2·Q. With u1 = 2^(wk), whose one nonzero digit is 1 in window k, and Q = ±2^(wk)·u2⁻¹·G, that one addition meets u2·Q = ±2^(wk)·G, the same point or its opposite.
	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task MultiplyAddWithTheTableMeetsEqualAndOppositePoints(CurveCase curve)
	{
		EcReference reference = curve.Reference;
		BigInteger n = curve.Order;
		Random random = new(15);
		List<string> failures = [];

		foreach (int k in (int[])[0, 1, curve.GeneratorWindowCount / 2, curve.GeneratorWindowCount - 1])
		{
			BigInteger u1 = BigInteger.One << curve.GeneratorWindowWidth * k;
			BigInteger u2 = 1 + EcReference.RandomBelow(random, n - 1);
			BigInteger q = u1 * BigInteger.ModPow(u2, n - 2, n) % n;
			Check(failures, curve, u1, reference.PublicKey(q), u2, reference.Multiply(reference.Generator, 2 * u1 % n));
			Check(failures, curve, u1, reference.PublicKey(n - q), u2, null);
		}

		await Assert.That(failures).IsEmpty();
	}

	// With n < p < 2n, x mod n is x − n for x in [n, p): the least such x above n here, where r = x − n fails the comparison of x with r and passes that with r + n, and the least x from n, which may be n itself, with x mod n = 0 below every r. A small x leaves r + n < p for r near x, so a wrong r there reaches the second comparison and fails it; an x near p − n leaves r + n ≥ p, as does r = x + p − n, whose r + n ≡ x would match without the bound.
	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task XModOrderEqualsMatchesTheReference(CurveCase curve)
	{
		EcReference reference = curve.Reference;
		BigInteger n = curve.Order;
		BigInteger p = reference.P;
		Random random = new(6);
		CurvePoint above = reference.PointWithXFrom(n + 1);
		List<CurvePoint> points = [reference.Generator, above, reference.PointWithXFrom(n), reference.PointWithXFrom(1), reference.PointWithXFrom(p - n)];
		List<string> failures = [];
		int wrapping = 0;

		for (int i = 0; i < RandomCount; ++i)
		{
			points.Add(reference.RandomPoint(random));
		}

		foreach (CurvePoint point in points)
		{
			BigInteger x = point.X % n;
			// r = x + R − n, for R the range of the limbs of a scalar, makes r + n carry out of the limbs and leave x in them, which would match without the carry; it is below n only where R < 2n.
			BigInteger wrapped = point.X + curve.ScalarLimbRange - n;

			foreach (BigInteger r in (BigInteger[])[x, x - 1, x + 1, point.X + p - n, wrapped])
			{
				if (r < 1 || r >= n)
				{
					continue;
				}

				if (r == wrapped)
				{
					++wrapping;
				}

				for (int i = 0; i < 2; ++i)
				{
					if (curve.XModOrderEqualsVariableTime(reference.RandomizeJacobian(point, random), r) != (r == x))
					{
						failures.Add($"{Show(point)} with r = {r:X}");
					}
				}
			}
		}

		foreach (BigInteger r in (BigInteger[])[1, n - 1])
		{
			if (curve.XModOrderEqualsVariableTime(reference.RandomizeJacobian(null, random), r))
			{
				failures.Add($"O with r = {r:X}");
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(n < p && p < 2 * n).IsTrue();
			await Assert.That(above.X < p).IsTrue();
			await Assert.That(wrapping > 0).IsEqualTo(curve.ScalarLimbRange < 2 * n);
			await Assert.That(failures).IsEmpty();
		}
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task GeneratorTableHoldsTheOddMultiples(CurveCase curve)
	{
		EcReference reference = curve.Reference;
		CurvePoint[] table = curve.VariableTimeGeneratorTable();
		CurvePoint? twice = reference.Add(reference.Generator, reference.Generator);
		CurvePoint? multiple = reference.Generator;
		List<string> failures = [];

		await Assert.That(table.Length).IsEqualTo(1 << curve.VariableTimeGeneratorWidth - 2);

		for (int j = 0; j < table.Length; ++j)
		{
			if (table[j] != multiple)
			{
				failures.Add($"entry {j}");
			}

			multiple = reference.Add(multiple, twice);
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task PointTableHoldsTheOddMultiplesOfEachPart(CurveCase curve)
	{
		EcReference reference = curve.Reference;
		CurvePoint point = reference.RandomPoint(new Random(16));
		CurvePoint[] table = curve.VariableTimePointTable(point);
		List<BigInteger> scalars = [];

		for (int c = 0; c < curve.PointTablePartCount; ++c)
		{
			for (int j = 1; j < 1 << curve.PointTableWidth - 1; j += 2)
			{
				scalars.Add((BigInteger)j << c * curve.PointTablePartLength);
			}
		}

		CurvePoint?[] multiples = reference.Multiply(point, scalars);

		using (Assert.Multiple())
		{
			await Assert.That(table.Length).IsEqualTo(multiples.Length);
			await Assert.That(Enumerable.Range(0, Math.Min(table.Length, multiples.Length)).Where(i => table[i] != multiples[i])).IsEmpty();
		}
	}

	// The table path recodes each part of u2 from the bits of that part alone.
	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task RecodeGivesTheNaf(CurveCase curve)
	{
		int length = curve.PointTablePartLength;
		List<string> failures = [];

		foreach (int width in Widths)
		{
			foreach (BigInteger scalar in RecodeScalars(curve, width))
			{
				int top = curve.RecodeVariableTime(scalar, width, out int[] digits);
				CheckNaf(failures, $"w = {width}, {scalar:X}", scalar, width, curve.ScalarBitLength, top, digits);

				for (int start = 0; start < curve.ScalarBitLength; start += length)
				{
					top = curve.RecodeVariableTime(scalar, start, length, width, out digits);
					CheckNaf(failures, $"w = {width}, {scalar:X} from bit {start}", scalar >> start & (BigInteger.One << length) - 1, width, length, top, digits);
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// value has length bits, which take length + 1 digits.
	private static void CheckNaf(List<string> failures, string operation, BigInteger value, int width, int length, int top, int[] digits)
	{
		BigInteger sum = 0;
		int previous = int.MinValue / 2;
		int highest = -1;
		bool valid = digits.Length == length + 1;

		for (int i = 0; i < digits.Length; ++i)
		{
			int digit = digits[i];
			sum += (BigInteger)digit << i;

			if (digit is 0)
			{
				continue;
			}

			valid &= int.IsOddInteger(digit) && Math.Abs(digit) < 1 << width - 1 && i - previous >= width;
			previous = i;
			highest = i;
		}

		if (!valid || sum != value || top != highest)
		{
			failures.Add($"{operation}: top {top}, digits {string.Join(", ", digits)}");
		}
	}

	// With and without the table of the point.
	private static void Check(List<string> failures, CurveCase curve, BigInteger u1, CurvePoint point, BigInteger u2, CurvePoint? expected)
	{
		string operation = $"{u1:X} · G + {u2:X} · {Show(point)}";
		CheckPoint(failures, curve.Reference, operation, curve.MultiplyAddVariableTime(u1, point, u2), expected);
		CheckPoint(failures, curve.Reference, $"{operation} with the table", curve.MultiplyAddWithTableVariableTime(u1, point, u2), expected);
	}

	private static BigInteger[] EdgeScalars(CurveCase curve)
	{
		BigInteger top = BigInteger.One << curve.ScalarBitLength - 1;
		return [0, 1, curve.Order - 1, top, top - 1, top + 1];
	}

	// Windows of w bits that each hold 2^w − 1, 2^(w − 1) + 1 or 2^(w − 1) − 1 give the longest carries and the largest digits of either sign.
	private static IEnumerable<BigInteger> RecodeScalars(CurveCase curve, int width)
	{
		BigInteger n = curve.Order;
		SortedSet<BigInteger> scalars = [.. EdgeScalars(curve), 2, n - 2, (n - 1) / 2, (n + 1) / 2];

		for (int k = 0; k < curve.ScalarBitLength; ++k)
		{
			scalars.Add(BigInteger.One << k);
			scalars.Add((BigInteger.One << k) - 1);
		}

		int half = 1 << width - 1;

		foreach ((int window, int windowWidth) in ((int, int)[])[(2 * half - 1, width), (half + 1, width), (half - 1, width), (0b01, 2), (0b10, 2)])
		{
			BigInteger scalar = 0;

			for (int i = 0; i < curve.ScalarBitLength / windowWidth; ++i)
			{
				BigInteger next = scalar | (BigInteger)window << i * windowWidth;

				if (next >= n)
				{
					break;
				}

				scalar = next;
			}

			scalars.Add(scalar);
		}

		Random random = new(width);

		for (int i = 0; i < RandomCount; ++i)
		{
			scalars.Add(EcReference.RandomBelow(random, n));
		}

		return scalars;
	}
}
