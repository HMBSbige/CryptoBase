using System.Collections.Concurrent;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.ECTestUtils;

namespace CryptoBase.Tests.EllipticCurves;

public class ScalarMultiplicationTest
{
	private const int RandomCount = 16;

	// The width w of the windows of k·P.
	private const int MultiplyWindowWidth = 5;

	private const int MultiplyWindowLength = 1 << MultiplyWindowWidth - 1;

	private static readonly int[] PatternWidths = [3, 4, 5, 6, 7];

	// The products of the scalars around each power of 2, which the tests of the same point share.
	private static readonly ConcurrentDictionary<(string Curve, CurvePoint Point), Lazy<(BigInteger Scalar, CurvePoint? Product)[]>> PowerProducts = new();

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
		CurvePoint point = MultiplyPoint(curve, pointIndex);
		List<string> failures = [];

		foreach ((BigInteger scalar, CurvePoint? expected) in Cases(curve, point, 3))
		{
			CheckPoint(failures, curve.Reference, $"{scalar:X} · {Show(point)}", curve.Multiply(point, scalar), expected);
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(nameof(MultiplyCases))]
	public async Task MultiplyHandlesExceptionalScalars(CurveCase curve, int pointIndex)
	{
		CurvePoint point = MultiplyPoint(curve, pointIndex);
		BigInteger[] scalars = [.. ExceptionalScalars(curve)];
		List<string> failures = [];

		foreach ((BigInteger scalar, CurvePoint? expected) in scalars.Zip(curve.Reference.Multiply(point, scalars)))
		{
			CheckPoint(failures, curve.Reference, $"{scalar:X} · {Show(point)}", curve.Multiply(point, scalar), expected);
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task MultiplyBaseHandlesExceptionalScalars(CurveCase curve)
	{
		BigInteger[] scalars = [.. ExceptionalScalars(curve)];
		List<string> failures = [];

		foreach ((BigInteger scalar, CurvePoint? expected) in scalars.Zip(curve.Reference.Multiply(curve.Reference.Generator, scalars)))
		{
			CheckPoint(failures, curve.Reference, $"{scalar:X} · G", curve.MultiplyBase(scalar), expected);
		}

		await Assert.That(failures).IsEmpty();
	}

	// Follows the digits of both multiplications on the scalars alone to find the additions of equal points, which only P-521 and SM2 have, at k = n − 18 and k = n − 6: there the last addition of k·P adds −9·P or −3·P to itself. The tests above would miss a wrong result there if the scalars did not hold it.
	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task ExceptionalScalarsMeetEqualPointsOnlyWhereExpected(CurveCase curve)
	{
		BigInteger n = curve.Order;
		List<string> found = [];

		foreach (BigInteger scalar in ExceptionalScalars(curve))
		{
			found.AddRange(EqualAdditions(curve, scalar).Select(addition => $"n − {n - scalar}: {addition}"));
		}

		string[] expected = curve.Name switch
		{
			"secp521r1" => ["n − 18: k·P in window 0"],
			CurveCase.SM2Name => ["n − 6: k·P in window 0"],
			_ => []
		};
		await Assert.That(found).IsEquivalentTo(expected);
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

	// The entry takes k in [1, n − 1] and normalizes k·G and k·P with one inversion; each must match its own normalization.
	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task MultiplyEncodeExportXMatchesSeparateNormalizations(CurveCase curve)
	{
		CurvePoint point = curve.Reference.RandomPoint(new Random(9));
		List<string> failures = [];

		foreach ((BigInteger scalar, CurvePoint? expected) in Cases(curve, point, 10))
		{
			if (scalar.IsZero)
			{
				continue;
			}

			(byte[] encoded, byte[] x) = curve.MultiplyEncodeExportX(point, scalar);
			byte[] separateX = new byte[curve.FieldLength];
			bool valid = curve.TryMultiplyExportX(point, scalar, separateX);

			if (expected is null || !valid || !encoded.AsSpan().SequenceEqual(curve.Encode(curve.MultiplyBaseToAffine(scalar))) || !x.AsSpan().SequenceEqual(separateX) || !x.AsSpan().SequenceEqual(curve.EncodeCoordinate(expected.X)))
			{
				failures.Add($"{scalar:X}: {Convert.ToHexString(encoded)}, {Convert.ToHexString(x)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// MultiplyEncode with the table of a public point P takes k in [1, n − 1]: k·G and k·P must match the reference, from the kernels of a curve that has them and the windows of ECGroup otherwise, for the scalars of ExceptionalScalars, whose windows of G the table of P shares, and for random scalars.
	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task MultiplyEncodeWithTheTableMatchesTheReference(CurveCase curve)
	{
		CurvePoint point = MultiplyPoint(curve, 1);
		object pointWindows = curve.PointWindows(point);
		Random random = new(11);
		BigInteger[] scalars = [.. ExceptionalScalars(curve).Concat(Enumerable.Range(0, RandomCount / 2).Select(_ => ECReference.RandomBelow(random, curve.Order - 1) + 1))];
		CurvePoint?[] products = curve.Reference.Multiply(point, scalars);
		CurvePoint?[] baseProducts = curve.Reference.Multiply(curve.Reference.Generator, scalars);
		List<string> failures = [];

		for (int i = 0; i < scalars.Length; ++i)
		{
			(byte[] encodedBase, byte[] encodedProduct) = curve.MultiplyEncode(pointWindows, scalars[i]);

			if (products[i] is not { } product || baseProducts[i] is not { } baseProduct || !encodedProduct.AsSpan().SequenceEqual(curve.Encode(product)) || !encodedBase.AsSpan().SequenceEqual(curve.Encode(baseProduct)))
			{
				failures.Add($"{scalars[i]:X} · {Show(point)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// k·P + l·Q from the table of P and from P itself, with Q = c·P for a known c, so that l = ∓k/c makes the sum the point at infinity or a double: k from ExceptionalScalars and 0 with l random, 0 and ∓k/c, the same scalars for Q with a random one for P, and both 0.
	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task MultiplyAddEncodeMatchesTheReference(CurveCase curve)
	{
		ECReference reference = curve.Reference;
		BigInteger n = curve.Order;
		CurvePoint point = MultiplyPoint(curve, 2);
		object pointWindows = curve.PointWindows(point);
		Random random = new(12);
		BigInteger c = ECReference.RandomBelow(random, n - 1) + 1;
		CurvePoint other = reference.Multiply(point, c) ?? throw new InvalidOperationException("c·P is the point at infinity.");
		BigInteger inverse = ECReference.Inverse(c, n);
		List<(BigInteger K, BigInteger L)> pairs = [(0, 0)];

		foreach (BigInteger k in ExceptionalScalars(curve).Prepend(0))
		{
			pairs.Add((k, ECReference.RandomBelow(random, n)));
			pairs.Add((k, 0));
			pairs.Add((k, k * inverse % n));
			pairs.Add((k, (n - k * inverse % n) % n));
			pairs.Add((ECReference.RandomBelow(random, n), k));
		}

		CurvePoint?[] sums = reference.Multiply(point, [.. pairs.Select(pair => (pair.K + pair.L * c) % n)]);
		List<string> failures = [];

		for (int i = 0; i < pairs.Count; ++i)
		{
			(BigInteger k, BigInteger l) = pairs[i];
			byte[]? expected = sums[i] is { } sum ? curve.Encode(sum) : null;
			byte[]? fromTable = curve.MultiplyAddEncode(pointWindows, k, other, l);
			byte[]? fromPoint = curve.MultiplyAddEncode(point, k, other, l);

			if (expected is null ? fromTable is not null : fromTable is null || !fromTable.AsSpan().SequenceEqual(expected))
			{
				failures.Add($"{k:X} · P + {l:X} · Q from the table of P");
			}

			if (expected is null ? fromPoint is not null : fromPoint is null || !fromPoint.AsSpan().SequenceEqual(expected))
			{
				failures.Add($"{k:X} · P + {l:X} · Q");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task MinusOneTimesGIsMinusG(CurveCase curve)
	{
		ECReference reference = curve.Reference;
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
		ECReference reference = curve.Reference;
		BigInteger n = curve.Order;
		Random random = new(4);
		List<BigInteger> scalars = [0, 1, 2, 3, n - 2, n - 1, (n - 1) / 2];
		List<string> failures = [];

		for (int i = 0; i < RandomCount; ++i)
		{
			scalars.Add(ECReference.RandomBelow(random, n));
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
		ECReference reference = curve.Reference;
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
		ECReference reference = curve.Reference;
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

			for (int digit = -half; digit <= half; ++digit)
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

	// The multiples stand for 1·P to 2^(w − 1)·P; a digit of 0 gives (0, 0).
	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task SelectFromMultiplesGivesEveryDigit(CurveCase curve)
	{
		Random random = new(9);
		BigInteger p = curve.FieldModulus;
		CurvePoint[] multiples = [.. Enumerable.Range(0, MultiplyWindowLength).Select(_ => new CurvePoint(ECReference.RandomBelow(random, p), ECReference.RandomBelow(random, p)))];
		List<string> failures = [];

		for (int digit = 1 - MultiplyWindowLength; digit <= MultiplyWindowLength; ++digit)
		{
			CurvePoint entry = digit is 0 ? new CurvePoint(0, 0) : multiples[Math.Abs(digit) - 1];
			CurvePoint expected = digit < 0 ? entry with { Y = (p - entry.Y) % p } : entry;
			CurvePoint actual = curve.SelectFromMultiples(multiples, digit);

			if (actual != expected)
			{
				failures.Add($"digit {digit}: {Show(actual)}, expected {Show(expected)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(nameof(MultiplyCases))]
	public async Task MultiplesHoldEachMultiple(CurveCase curve, int pointIndex)
	{
		CurvePoint point = MultiplyPoint(curve, pointIndex);
		CurvePoint[] multiples = curve.Multiples(point, MultiplyWindowLength);
		CurvePoint?[] expected = curve.Reference.Multiply(point, [.. Enumerable.Range(1, MultiplyWindowLength).Select(static j => (BigInteger)j)]);

		using (Assert.Multiple())
		{
			await Assert.That(multiples.Length).IsEqualTo(expected.Length);
			await Assert.That(Enumerable.Range(0, Math.Min(multiples.Length, expected.Length)).Where(i => multiples[i] != expected[i])).IsEmpty();
		}
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
		ECReference reference = curve.Reference;
		BigInteger n = curve.Order;

		foreach ((BigInteger scalar, CurvePoint? product) in PowerProducts.GetOrAdd((curve.Name, point), key => new Lazy<(BigInteger, CurvePoint?)[]>(() => ComputePowerProducts(curve, key.Point))).Value)
		{
			yield return (scalar, product);
		}

		SortedSet<BigInteger> scalars = [2, 3, n - 1, n - 2, n - 3, (n - 1) / 2, (n + 1) / 2];

		foreach ((_, BigInteger scalar, _) in PatternScalars(curve))
		{
			scalars.Add(scalar);
		}

		Random random = new(seed);

		for (int i = 0; i < RandomCount; ++i)
		{
			scalars.Add(ECReference.RandomBelow(random, n));
		}

		foreach ((BigInteger scalar, CurvePoint? product) in scalars.Zip(reference.Multiply(point, scalars)))
		{
			yield return (scalar, product);
		}
	}

	// 2^k, 2^k − 1 and 2^k + 1 for each bit k of n; each step takes the three sums with a single inversion.
	private static (BigInteger, CurvePoint?)[] ComputePowerProducts(CurveCase curve, CurvePoint point)
	{
		List<(BigInteger, CurvePoint?)> products = [];
		CurvePoint? power = point;
		CurvePoint? belowPower = null;

		for (int k = 0; k < curve.ScalarBitLength; ++k)
		{
			CurvePoint?[] sums = curve.Reference.Add([power, belowPower, power], [point, power, power]);
			products.Add((BigInteger.One << k, power));
			products.Add(((BigInteger.One << k) - 1, belowPower));
			products.Add(((BigInteger.One << k) + 1, sums[0]));
			belowPower = sums[1];
			power = sums[2];
		}

		return [.. products];
	}

	private static CurvePoint MultiplyPoint(CurveCase curve, int pointIndex)
	{
		Random random = new(2);
		CurvePoint[] points = [curve.Reference.Generator, curve.Reference.RandomPoint(random), curve.Reference.RandomPoint(random)];
		return points[pointIndex];
	}

	// Scalars around the additions that may meet equal points or the point at infinity. As k = 2^w·a + d for the low digit d of k·P, its last addition adds d·P to itself just if k ≡ 2d, which for d < 0 is n + 2d; n − 2^j ends in a run of carries; 2^(wi) leaves the point at infinity in the accumulator up to window i; and around the top window t of each width w come 2^(wt) and n − 2^(wt) with their neighbors, d·2^(wt), and 2d·2^(wt) − n, which would have the top addition of k·G add d·2^(wt)·G to itself; where w divides the bits of n, LargestOwnDigits, the largest k whose digits for G are those of k and not of k − n, comes with its neighbors.
	private static SortedSet<BigInteger> ExceptionalScalars(CurveCase curve)
	{
		BigInteger n = curve.Order;
		int bits = curve.ScalarBitLength;
		SortedSet<BigInteger> scalars = [1, n - 1];

		for (int d = 1; d <= MultiplyWindowLength; ++d)
		{
			scalars.Add(2 * d);
			scalars.Add(n - 2 * d);
		}

		for (int j = 0; j <= 2 * Math.Max(MultiplyWindowWidth, curve.GeneratorWindowWidth); ++j)
		{
			scalars.Add(n - (BigInteger.One << j));
		}

		foreach (int width in (int[])[MultiplyWindowWidth, curve.GeneratorWindowWidth])
		{
			int top = bits / width * width;
			BigInteger power = BigInteger.One << top;

			for (int i = 0; i < top; i += width)
			{
				scalars.Add(BigInteger.One << i);
			}

			for (int s = -2; s <= 2; ++s)
			{
				scalars.Add(power + s);
				scalars.Add(n - power + s);
			}

			for (BigInteger multiple = power; multiple < n; multiple += power)
			{
				scalars.Add(multiple);
				scalars.Add(2 * multiple - n);
			}

			if (bits % width is 0)
			{
				BigInteger largest = LargestOwnDigits(bits, width);

				for (int s = -2; s <= 2; ++s)
				{
					scalars.Add(largest + s);
				}
			}
		}

		scalars.RemoveWhere(scalar => scalar < 0 || scalar >= n);
		return scalars;
	}

	// The additions of equal points, neither at infinity, that the digits lead to: in k·P, of d·P to the accumulator 2^w·a·P left by the doublings, from the top window down; in k·G, of d·2^(wi)·G to the sum L·G of the windows below i.
	private static IEnumerable<string> EqualAdditions(CurveCase curve, BigInteger scalar)
	{
		BigInteger n = curve.Order;
		int[] digits = Recode(scalar, MultiplyWindowWidth, curve.ScalarBitLength / MultiplyWindowWidth + 1);
		BigInteger accumulator = digits[^1];

		for (int i = digits.Length - 2; i >= 0; --i)
		{
			accumulator <<= MultiplyWindowWidth;

			if (IsEqualAddition(accumulator, digits[i], n))
			{
				yield return $"k·P in window {i}";
			}

			accumulator += digits[i];
		}

		int width = curve.GeneratorWindowWidth;
		digits = GeneratorDigits(curve, scalar);
		BigInteger sum = 0;

		for (int i = 0; i < digits.Length; ++i)
		{
			BigInteger entry = (BigInteger)digits[i] << i * width;

			if (IsEqualAddition(sum, entry, n))
			{
				yield return $"k·G in window {i}";
			}

			sum += entry;
		}
	}

	private static bool IsEqualAddition(BigInteger left, BigInteger right, BigInteger n)
	{
		return !(left % n).IsZero && !(right % n).IsZero && ((left - right) % n).IsZero;
	}

	// 2^(w − 1) is the largest digit and carries nothing. 2^(w − 1) + 1 gives the most negative digit, 1 − 2^(w − 1), and then 2 − 2^(w − 1) in each window above, each with a carry out. 2^w − 1 gives −1 and then 0s, with a carry that runs through every window. The carry out of the last window is the digit above it.
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

	// The digits of the windows of G: where w divides N, the bits of n, those in [−2^(w − 1), 2^(w − 1) − 1] of k up to LargestOwnDigits and of k − n above it, from 2^N + k − n; otherwise those of Recode.
	private static int[] GeneratorDigits(CurveCase curve, BigInteger scalar)
	{
		int width = curve.GeneratorWindowWidth;
		int bits = curve.ScalarBitLength;

		if (bits % width is not 0)
		{
			return Recode(scalar, width, curve.GeneratorWindowCount);
		}

		BigInteger value = scalar <= LargestOwnDigits(bits, width) ? scalar : scalar - curve.Order + (BigInteger.One << bits);
		int half = 1 << width - 1;
		int[] digits = new int[bits / width];
		int carry = 0;

		for (int i = 0; i < digits.Length; ++i)
		{
			int window = (int)(value >> i * width & (1 << width) - 1) + carry;
			carry = window >= half ? 1 : 0;
			digits[i] = window - (carry << width);
		}

		return digits;
	}

	// Every window 2^(w − 1) − 1 over the N bits, the largest sum of digits in [−2^(w − 1), 2^(w − 1) − 1].
	private static BigInteger LargestOwnDigits(int bits, int width)
	{
		return Repeat((1 << width - 1) - 1, width, bits / width);
	}
}
