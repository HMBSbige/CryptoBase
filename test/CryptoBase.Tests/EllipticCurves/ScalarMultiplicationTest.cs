using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.EcTestUtils;

namespace CryptoBase.Tests.EllipticCurves;

public class ScalarMultiplicationTest
{
	private const int RandomCount = 16;

	// 2^(w − 1) for the width of k·P.
	private const int MultiplyWindowLength = 16;

	private static readonly int[] PatternWidths = [3, 4, 5, 6, 7];

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task MultiplyBaseMatchesTheReference(CurveCase curve)
	{
		List<string> failures = [];

		foreach ((BigInteger scalar, CurvePoint? expected) in Cases(curve, curve.Reference.Generator, 1))
		{
			CheckPoint(failures, curve.Reference, $"{scalar:X} · G", curve.MultiplyBase(scalar), expected);
		}

		await Assert.That(failures).IsEmpty();
	}

	// A test of its own for each point, so that the points of the larger curves multiply in parallel.
	public static IEnumerable<(CurveCase Curve, int PointIndex)> MultiplyCases()
	{
		foreach (CurveCase curve in CurveCase.All())
		{
			for (int pointIndex = 0; pointIndex < 3; ++pointIndex)
			{
				yield return (curve, pointIndex);
			}
		}
	}

	[Test]
	[MethodDataSource(nameof(MultiplyCases))]
	public async Task MultiplyMatchesTheReference(CurveCase curve, int pointIndex)
	{
		Random random = new(2);
		CurvePoint[] points = [curve.Reference.Generator, curve.Reference.RandomPoint(random), curve.Reference.RandomPoint(random)];
		CurvePoint point = points[pointIndex];
		List<string> failures = [];

		foreach ((BigInteger scalar, CurvePoint? expected) in Cases(curve, point, 3))
		{
			CheckPoint(failures, curve.Reference, $"{scalar:X} · {Show(point)}", curve.Multiply(point, scalar), expected);
		}

		await Assert.That(failures).IsEmpty();
	}

	// The entry takes k in [1, n − 1].
	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task MultiplyBaseToAffineMatchesTheReference(CurveCase curve)
	{
		List<string> failures = [];

		foreach ((BigInteger scalar, CurvePoint? expected) in Cases(curve, curve.Reference.Generator, 5))
		{
			if (scalar.IsZero)
			{
				continue;
			}

			CurvePoint actual = curve.MultiplyBaseToAffine(scalar);

			if (actual != expected)
			{
				failures.Add($"{scalar:X}: {Show(actual)}, expected {Show(expected)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The entry takes k in [1, n − 1].
	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task MultiplyBaseReduceXMatchesTheReference(CurveCase curve)
	{
		List<string> failures = [];

		foreach ((BigInteger scalar, CurvePoint? expected) in Cases(curve, curve.Reference.Generator, 6))
		{
			if (scalar.IsZero)
			{
				continue;
			}

			BigInteger actual = curve.MultiplyBaseReduceX(scalar);

			if (expected is null || actual != expected.X % curve.Order)
			{
				failures.Add($"{scalar:X}: {actual:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task TryMultiplyExportXMatchesTheReference(CurveCase curve)
	{
		byte[] untouched = [.. Enumerable.Repeat((byte)0xA5, curve.FieldLength)];
		CurvePoint point = curve.Reference.RandomPoint(new Random(7));
		List<string> failures = [];

		foreach ((BigInteger scalar, CurvePoint? expected) in Cases(curve, point, 8))
		{
			byte[] destination = [.. untouched];
			bool valid = curve.TryMultiplyExportX(point, scalar, destination);

			if (valid != expected is not null || !destination.AsSpan().SequenceEqual(expected is null ? untouched : curve.EncodeCoordinate(expected.X)))
			{
				failures.Add($"{scalar:X}: {valid}, {Convert.ToHexString(destination)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task MinusOneTimesGIsMinusG(CurveCase curve)
	{
		EcReference reference = curve.Reference;
		CurvePoint? minusG = reference.Negate(reference.Generator);

		using (Assert.Multiple())
		{
			await Assert.That(reference.ToAffine(curve.MultiplyBase(curve.Order - 1))).IsEqualTo(minusG);
			await Assert.That(reference.ToAffine(curve.Multiply(reference.Generator, curve.Order - 1))).IsEqualTo(minusG);
		}
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task BothMultiplicationsAgreeOnG(CurveCase curve)
	{
		EcReference reference = curve.Reference;
		BigInteger n = curve.Order;
		Random random = new(4);
		List<BigInteger> scalars = [0, 1, 2, 3, n - 2, n - 1, (n - 1) / 2];
		List<string> failures = [];

		for (int i = 0; i < RandomCount; ++i)
		{
			scalars.Add(EcReference.RandomBelow(random, n));
		}

		foreach (BigInteger scalar in scalars)
		{
			CurvePoint? fromTable = reference.ToAffine(curve.MultiplyBase(scalar));
			CurvePoint? fromMultiples = reference.ToAffine(curve.Multiply(reference.Generator, scalar));

			if (fromTable != fromMultiples)
			{
				failures.Add($"{scalar:X}: {Show(fromTable)} and {Show(fromMultiples)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task GeneratorTableHoldsTheMultiples(CurveCase curve)
	{
		EcReference reference = curve.Reference;
		CurvePoint[] table = curve.GeneratorTable();
		CurvePoint? windowBase = reference.Generator;
		List<string> failures = [];

		await Assert.That(table.Length).IsEqualTo(curve.GeneratorWindowCount * curve.GeneratorWindowLength);

		for (int i = 0; i < curve.GeneratorWindowCount; ++i)
		{
			CurvePoint? multiple = null;

			for (int j = 0; j < curve.GeneratorWindowLength; ++j)
			{
				multiple = reference.Add(multiple, windowBase);

				if (table[i * curve.GeneratorWindowLength + j] != multiple)
				{
					failures.Add($"window {i}, entry {j}");
				}
			}

			for (int k = 0; k < curve.GeneratorWindowWidth; ++k)
			{
				windowBase = reference.Add(windowBase, windowBase);
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task SelectFromGeneratorTableGivesEveryDigit(CurveCase curve)
	{
		EcReference reference = curve.Reference;
		int half = curve.GeneratorWindowLength;
		CurvePoint? windowBase = reference.Generator;
		List<string> failures = [];

		for (int i = 0; i < curve.GeneratorWindowCount; ++i)
		{
			CurvePoint?[] multiples = new CurvePoint?[half + 1];

			for (int j = 1; j <= half; ++j)
			{
				multiples[j] = reference.Add(multiples[j - 1], windowBase);
			}

			for (int digit = 1 - half; digit <= half; ++digit)
			{
				CurvePoint expected = (digit < 0 ? reference.Negate(multiples[-digit]) : multiples[digit]) ?? new CurvePoint(0, 0);
				CurvePoint actual = curve.SelectFromGeneratorTable(i, digit);

				if (actual != expected)
				{
					failures.Add($"window {i}, digit {digit}: {Show(actual)}, expected {Show(expected)}");
				}
			}

			for (int k = 0; k < curve.GeneratorWindowWidth; ++k)
			{
				windowBase = reference.Add(windowBase, windowBase);
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task SelectFromMultiplesGivesEveryDigit(CurveCase curve)
	{
		Random random = new(9);
		BigInteger p = curve.FieldModulus;
		ProjectiveValue[] multiples = [.. Enumerable.Range(0, MultiplyWindowLength + 1).Select(_ => new ProjectiveValue(EcReference.RandomBelow(random, p), EcReference.RandomBelow(random, p), EcReference.RandomBelow(random, p)))];
		List<string> failures = [];

		for (int digit = 1 - MultiplyWindowLength; digit <= MultiplyWindowLength; ++digit)
		{
			ProjectiveValue entry = multiples[Math.Abs(digit)];
			ProjectiveValue expected = digit < 0 ? entry with { Y = (p - entry.Y) % p } : entry;
			ProjectiveValue actual = curve.SelectFromMultiples(multiples, digit);

			if (actual != expected)
			{
				failures.Add($"digit {digit}: {actual}, expected {expected}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task PatternScalarsGiveTheirDigits(CurveCase curve)
	{
		List<string> failures = [];

		foreach ((int width, BigInteger scalar, int[] digits) in PatternScalars(curve))
		{
			int[] recoded = Recode(scalar, width, digits.Length);

			if (scalar >= curve.Order || !recoded.AsSpan().SequenceEqual(digits))
			{
				failures.Add($"w = {width}, {scalar:X}: {string.Join(", ", recoded)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	private static IEnumerable<(BigInteger Scalar, CurvePoint? Expected)> Cases(CurveCase curve, CurvePoint point, int seed)
	{
		EcReference reference = curve.Reference;
		BigInteger n = curve.Order;
		CurvePoint? power = point;
		CurvePoint? belowPower = null;

		for (int k = 0; k < curve.ScalarBitLength; ++k)
		{
			yield return (BigInteger.One << k, power);
			yield return ((BigInteger.One << k) - 1, belowPower);
			yield return ((BigInteger.One << k) + 1, reference.Add(power, point));
			belowPower = reference.Add(belowPower, power);
			power = reference.Add(power, power);
		}

		SortedSet<BigInteger> scalars = [2, 3, n - 1, n - 2, n - 3, (n - 1) / 2, (n + 1) / 2];

		foreach ((_, BigInteger scalar, _) in PatternScalars(curve))
		{
			scalars.Add(scalar);
		}

		Random random = new(seed);

		for (int i = 0; i < RandomCount; ++i)
		{
			scalars.Add(EcReference.RandomBelow(random, n));
		}

		foreach ((BigInteger scalar, CurvePoint? product) in scalars.Zip(reference.Multiply(point, scalars)))
		{
			yield return (scalar, product);
		}
	}

	// 2^(w − 1) is the largest digit and carries nothing. 2^(w − 1) + 1 gives the most negative digit,
	// 1 − 2^(w − 1), and then 2 − 2^(w − 1) in each window above, each with a carry out. 2^w − 1 gives −1 and then 0s, with a carry that
	// runs through every window. The carry out of the last window is the digit above it.
	private static IEnumerable<(int Width, BigInteger Scalar, int[] Digits)> PatternScalars(CurveCase curve)
	{
		foreach (int width in PatternWidths)
		{
			int half = 1 << width - 1;

			foreach (int window in (int[])[half, half + 1, 2 * half - 1])
			{
				int count = curve.ScalarBitLength / width;
				BigInteger scalar;

				while ((scalar = Repeat(window, width, count)) >= curve.Order)
				{
					--count;
				}

				int[] digits = new int[curve.ScalarBitLength / width + 1];

				for (int i = 0; i < count; ++i)
				{
					digits[i] = (window - half, i) switch
					{
						(0, _) => half,
						(1, 0) => 1 - half,
						(1, _) => 2 - half,
						(_, 0) => -1,
						_ => 0,
					};
				}

				digits[count] = window == half ? 0 : 1;
				yield return (width, scalar, digits);
			}
		}
	}

	private static BigInteger Repeat(int window, int width, int count)
	{
		BigInteger result = 0;

		for (int i = 0; i < count; ++i)
		{
			result |= (BigInteger)window << i * width;
		}

		return result;
	}

	private static int[] Recode(BigInteger scalar, int width, int count)
	{
		int half = 1 << width - 1;
		int[] digits = new int[count];
		int carry = 0;

		for (int i = 0; i < count; ++i)
		{
			int value = (int)(scalar >> i * width & (1 << width) - 1) + carry;
			carry = value > half ? 1 : 0;
			digits[i] = value - (carry << width);
		}

		return digits;
	}
}
