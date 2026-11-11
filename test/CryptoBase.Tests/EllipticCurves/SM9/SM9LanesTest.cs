using CryptoBase.EllipticCurves.SM9;
using System.Numerics;
using System.Runtime.InteropServices;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9Reference;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9TestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.EllipticCurves.SM9;

// The arithmetic of SM9Lanes for every vector type the CPU supports, against the BigInteger reference.
public class SM9LanesTest
{
	// What the reference gives for the tests below, once for all the vectors.
	private static readonly Lazy<OperationCases> ReferenceOperations = new(ComputeReferenceOperations);

	private static readonly Lazy<OperationCases> ExtremeOperations = new(ComputeExtremeOperations);

	private static readonly Lazy<(SM9Fp12 Element, Fp12Value Square)[]> CyclotomicElements = new(ComputeCyclotomicElements);

	private static readonly Lazy<(SM9AffinePoint<SM9Fp> P, SM9AffinePoint<SM9Fp2> Q, G2Value Expected)[]> DoublingCases = new(ComputeDoublingCases);

	[Test]
	public async Task EveryVectorIsListed()
	{
		SkipUnlessJit();
		Type[] implementations = typeof(ISM9Vector<>).Assembly.GetTypes().Where(static type => type is { IsInterface: false, IsAbstract: false } && type.GetInterfaces().Any(static i => i.IsGenericType && i.GetGenericTypeDefinition() == typeof(ISM9Vector<>))).ToArray();

		await Assert.That(SM9LanesCase.All().Select(static vector => vector.VectorType)).IsEquivalentTo(implementations);
	}

	[Test]
	[MethodDataSource(typeof(SM9LanesCase), nameof(SM9LanesCase.All))]
	public async Task OperationsMatchTheReference(SM9LanesCase vector)
	{
		SkipUnlessSupported(vector);

		await Assert.That(vector.Accept(new Operations(ReferenceOperations.Value))).IsEmpty();
	}

	// The lazy reductions add products before reducing them, so their bounds are tightest at coefficients of extreme raw values, as in SM9TowerTest.
	[Test]
	[MethodDataSource(typeof(SM9LanesCase), nameof(SM9LanesCase.All))]
	public async Task LazyReductionsHoldAtTheExtremes(SM9LanesCase vector)
	{
		SkipUnlessSupported(vector);

		await Assert.That(vector.Accept(new Operations(ExtremeOperations.Value))).IsEmpty();
	}

	// The coefficient of w⁵ at 0 makes m of the pair of lanes 2 and 5 zero, so lane 1 of T takes its largest value, 4·3p, and the odd lanes add twice the largest input there: the rows of the narrower vectors reach F = 40.5p.
	[Test]
	[MethodDataSource(typeof(SM9LanesCase), nameof(SM9LanesCase.All))]
	public async Task CyclotomicSquaresHoldAtTheBoundsOfTheirRows(SM9LanesCase vector)
	{
		SkipUnlessSupported(vector);

		SM9Fp largest = Raw(ReducedBound - 1);
		SM9Fp ones = Raw((ReducedBound - 1 >> 208 << 208) - 1);
		SM9Fp zero = default;
		// Coefficients 10 and 11 of Pattern are those of w⁵, 6 and 7 those of w¹.
		List<SM9Fp12> values = [Pattern(i => i >= 10 ? zero : largest), Pattern(i => i >= 10 ? zero : ones), Pattern(i => i is 6 or 7 ? largest : zero), Pattern(i => i is 6 or 7 ? ones : i >= 10 ? zero : largest)];
		await Assert.That(vector.Accept(new CyclotomicFormulas(values))).IsEmpty();
	}

	// Elements f^((p⁶ − 1)(p² + 1)) lie in the cyclotomic subgroup, where the square of Granger and Scott holds.
	[Test]
	[MethodDataSource(typeof(SM9LanesCase), nameof(SM9LanesCase.All))]
	public async Task CyclotomicSquaresMatchSquares(SM9LanesCase vector)
	{
		SkipUnlessSupported(vector);

		await Assert.That(vector.Accept(new CyclotomicSquares(CyclotomicElements.Value))).IsEmpty();
	}

	// Elements whose cyclotomic square on AVX-512 takes the quotient of its weak reduction from F9 + ⌊F8/2^26⌋ one below the top limb of F carried, in lanes 3, 4 and 2 in turn: F8 lies just below a multiple of 2^26 there, and the limbs under it carry it past. The coefficients are raw values in the order of Pattern; the other vectors take them as any others.
	[Test]
	[MethodDataSource(typeof(SM9LanesCase), nameof(SM9LanesCase.All))]
	public async Task CyclotomicSquaresHoldWhereTheQuotientIsEstimatedLow(SM9LanesCase vector)
	{
		SkipUnlessSupported(vector);

		string[][] coefficients =
		[
			[
				"7064AF2713F68D4A0B1F6B745C57EC46A619DCCD7F794D7043D41E8E73A319DA",
				"69C11BC027012997FA6F60BCCD16558892FAB931F969E9A7BF276F70BC2509E0",
				"288BFFFF6E46242B9A7F71224D599E81FCD31812B681CD9D307CD5EAF4D2EC51",
				"419D300E8EC6C9386CE0679B677D3F2B2D108543ED931F9D997F9D9E27CDDF6F",
				"16D8AF0D7D4EE60FE08E4C10EC0D340369FE7ADEC5284B4D900E3D40639A236",
				"1729E8280EE6A53A99519833DD5CCE5826E28A808EE2E68D7C5C5627D7E20D93",
				"3CA5534D70819C48BBFB1FA410BB98B1F263E07026FD3391647C185FBCDA1999",
				"0E3D160B97C2741E1D7A2C066E50771B82C5C9735364A179E0B5F9690871E6BD",
				"6362D41E37F5E9536B90C44E54DB31EEBCD2D467977D2A30069E47EAF2F9B35B",
				"485CE76751009F8D2296F23962E51CDAEF9FB686FC01D667B230318FCB161812",
				"7A804ADF30EF3DF382209C017DB743475633CC6F8FEDE6A2AA005FF1BCBC55C0",
				"6657CBCF6FB3C83A3424184AA4A31FFACDD21E93A80B97B7E4BDE933E361C6E2",
			],
			[
				"221FC08744D20FBF915A53C08CC7A438155D6B4D4DF63C6E4BCDAC4E481F41D0",
				"1DADC489DA3F898DE67CBE9560AA68E7798D4048E66E333CB85617474E45C811",
				"5782F7CD7BEC05F4B52F04275589FCA45CF76AAEB2083D3708DF0C717A23BC7",
				"0BA4F4B53207B857E9D712A85424BE957012E3FA5C3BC1F01C771F62EA048092",
				"1DFC664518A9931BA880A8315370E667ABDD64EF172E5258E07F685ACAF6189A",
				"55F29A67BEC7AF4D97F269B7340D4E86295467D2A9C04F74A4563AA51CCA60C1",
				"5DD93D9773F6CF326D5878E9EE18BEEE552B48FFC058BCAE1AABC18F12042DE7",
				"63718237CAC0DF96D56F2867D9DC78689B664DD79AAD0819618DF7174F39EA97",
				"179629C23737B9647B6F0383FDC52ED88F815BD3AB6FCF8D8BC7D705F15D6856",
				"3863C8909F4C8DE1F85276E5AB545F3A3E84C32AFF58DA4E14A062A908E5819F",
				"76868400161C27EC2E28E4EB42CA87F8B3F63A7C162935E824CC2E869CD933E1",
				"2F6323B5125FAFAA0AFCECF6994197EC565365E22941FD878731B3A2AA8F4927",
			],
			[
				"5BFD118C77A8066A7BD89479674433863F0B379D0AE60E2AD74D85EE43391E3B",
				"11194AD6DDE8D9BD46A64461ED6A34CA4E1C6EC214F28FF69ECFD170077DD67F",
				"76ABC8F2E89649362F3A15ED93DDC2288B97A766E50483C8746215378E611E93",
				"58FF82797FED5731E37E1D7E3B88AD5151315660A2C09878071E92C0BB502E09",
				"18F68E9FA468896CB0EC623A221BA19765F3D58D797D748BBF2F68D046785D04",
				"7DFC208A0047D9C771A253B5E4E0E119FA82A46900A9F37C5844800AB9F95C13",
				"775CCD443930F188BABF33B416AC85AAE6E403B0426EBDCAD6218CACF9797991",
				"61FC92E85CBB71BEB95D30674F9AE01963D6172E3395EB0DBF546D00082BD81B",
				"6E7BD7F8B28F49727AEBC4A7C1ED2AD559D95A872A48A6565717A9DDB82A9417",
				"2B7F5F65199346B0A953D09F0E671202E116378F158A10F882363CAAAB8316BB",
				"11981D1DA863FBD9C3EA94DF13C5F5D17912E36460B3AF3EB6EE2BAE5643CBF5",
				"16219945C7B27C7FE1607917B96994A081634B489F21605879E6548AD36B99BC",
			],
		];
		List<SM9Fp12> values = coefficients.Select(static raw => Pattern(i => Raw(Parse(raw[i])))).ToList();

		await Assert.That(vector.Accept(new CyclotomicFormulas(values))).IsEmpty();
	}

	// The first two steps of the Miller loop double Q and 2Q: the lane steps must leave T as 4Q and give the lines of SM9MillerLoop.Precompute at P.
	[Test]
	[MethodDataSource(typeof(SM9LanesCase), nameof(SM9LanesCase.Rows))]
	public async Task DoublingStepsMatchTheScalarLines(SM9LanesCase vector)
	{
		SkipUnlessSupported(vector);

		List<string> failures = [];

		foreach ((SM9AffinePoint<SM9Fp> p, SM9AffinePoint<SM9Fp2> q, G2Value expected) in DoublingCases.Value)
		{
			failures.AddRange(vector.Accept(new DoublingSteps(p, q, expected)));
		}

		await Assert.That(failures).IsEmpty();
	}

	// The doubling step is an identity of the polynomials of its inputs, so coordinates of extreme raw values, which need not lie on the twist, take its lazy reductions to their bounds; so does its line, l0 unreduced, in a product with an extreme element.
	[Test]
	[MethodDataSource(typeof(SM9LanesCase), nameof(SM9LanesCase.Rows))]
	public async Task DoublingStepsHoldAtTheExtremes(SM9LanesCase vector)
	{
		SkipUnlessSupported(vector);

		Random random = new(7);
		SM9Fp largest = Raw(ReducedBound - 1);
		SM9Fp ones = Raw((ReducedBound - 1 >> 208 << 208) - 1);
		SM9Fp[] extremes = [default, largest, ones];
		List<string> failures = [];

		foreach (int k in Enumerable.Range(0, 24))
		{
			SM9Fp Pick()
			{
				return k < 3 ? extremes[k] : extremes[random.Next(extremes.Length)];
			}

			SM9Point<SM9Fp2> t = new() { X = new SM9Fp2 { A0 = Pick(), A1 = Pick() }, Y = new SM9Fp2 { A0 = Pick(), A1 = Pick() }, Z = new SM9Fp2 { A0 = Pick(), A1 = Pick() } };
			SM9Fp12 f = Pattern(_ => Pick());
			failures.AddRange(vector.Accept(new ExtremeDoubling(t, Pick(), Pick(), f)));
		}

		await Assert.That(failures).IsEmpty();
	}

	private static OperationCases ComputeReferenceOperations()
	{
		Random random = new(1);
		List<SM9Fp12> values = [Element(Fp12Value.One), Element(new Fp12Value(Enumerable.Repeat(new Fp2Value(P - 1, P - 1), 6).ToArray()))];

		for (int i = 0; i < 6; ++i)
		{
			values.Add(Element(RandomFp12(random)));
		}

		return new OperationCases(values, random);
	}

	private static OperationCases ComputeExtremeOperations()
	{
		Random random = new(5);
		SM9Fp largest = Raw(ReducedBound - 1);
		SM9Fp ones = Raw((ReducedBound - 1 >> 208 << 208) - 1);
		SM9Fp zero = default;
		SM9Fp[] extremes = [zero, largest, ones];
		List<SM9Fp12> values = [Pattern(_ => largest), Pattern(i => i % 2 is 0 ? zero : largest), Pattern(i => i % 2 is 0 ? largest : zero), Pattern(i => i % 2 is 0 ? zero : ones), Pattern(_ => ones)];

		for (int k = 0; k < 16; ++k)
		{
			values.Add(Pattern(_ => extremes[random.Next(extremes.Length)]));
		}

		return new OperationCases(values, random);
	}

	private static (SM9Fp12, Fp12Value)[] ComputeCyclotomicElements()
	{
		Random random = new(3);
		return [.. Enumerable.Range(0, 4).Select(_ =>
		{
			Fp12Value g = RandomFp12(random).Pow((BigInteger.Pow(P, 6) - 1) * (P * P + 1));
			return (Element(g), g * g);
		})];
	}

	private static (SM9AffinePoint<SM9Fp>, SM9AffinePoint<SM9Fp2>, G2Value)[] ComputeDoublingCases()
	{
		Random random = new(6);
		return [.. Enumerable.Range(0, 4).Select(_ =>
		{
			G1Value p = Multiply(P1, RandomBelow(random, N - 1) + 1)!;
			G2Value q = Multiply(P2, RandomBelow(random, N - 1) + 1)!;
			return (Element(p), Element(q), Multiply(q, 4)!);
		})];
	}

	// The twelve coefficients of Fp in the order C0.C0.A0, C0.C0.A1, C0.C1.A0, … C1.C2.A1.
	private static SM9Fp12 Pattern(Func<int, SM9Fp> coefficient)
	{
		SM9Fp12 value = default;
		Span<SM9Fp> limbs = MemoryMarshal.Cast<SM9Fp12, SM9Fp>(new Span<SM9Fp12>(ref value));

		for (int i = 0; i < limbs.Length; ++i)
		{
			limbs[i] = coefficient(i);
		}

		return value;
	}

	// (3c² − 2c̄) + (3V·a² + 2b̄)·w + (3b² − 2ā)·w² over Fp4 = Fp2[V], V = w³, which holds as an identity of the coefficients for any input.
	private static Fp12Value CyclotomicFormula(Fp12Value f)
	{
		(Fp2Value c0, Fp2Value c1) = (f.C[0], f.C[3]);
		(Fp2Value b0, Fp2Value b1) = (f.C[1], f.C[4]);
		(Fp2Value a0, Fp2Value a1) = (f.C[2], f.C[5]);
		(Fp2Value cr, Fp2Value cv) = Square(c0, c1);
		(Fp2Value br, Fp2Value bv) = Square(b0, b1);
		(Fp2Value ar, Fp2Value av) = Square(a0, a1);
		return new Fp12Value([cr * 3 - c0 * 2, av * U * 3 + b0 * 2, br * 3 - a0 * 2, cv * 3 + c1 * 2, ar * 3 - b1 * 2, bv * 3 + a1 * 2]);

		static (Fp2Value Real, Fp2Value V) Square(Fp2Value x0, Fp2Value x1)
		{
			return (x0 * x0 + x1 * x1 * U, x0 * x1 * 2);
		}
	}

	private static void Check(List<string> failures, string operation, in SM9Fp12 actual, Fp12Value expected)
	{
		if (!IsReduced(actual) || ValueOf(actual) != expected)
		{
			failures.Add($"{operation} gave {ValueOf(actual)}, expected {expected}");
		}
	}

	// The reference results for each element x and each pair (x, y), with a random line for the aliased product of each x.
	private sealed class OperationCases
	{
		internal readonly record struct PairProducts(Fp12Value Product, Fp12Value ByLine, Fp12Value ByNormalizedLine, Fp12Value LinePair, Fp12Value ByLinePair);

		internal readonly record struct ElementResults(Fp12Value Value, Fp12Value Square, Fp12Value Cyclotomic, Fp12Value Frobenius, Fp12Value FrobeniusSquared, Fp12Value FrobeniusCubed, Fp12Value Conjugate, SM9Fp12 Line, Fp12Value ByLine);

		internal OperationCases(List<SM9Fp12> values, Random random)
		{
			Values = values;
			Fp12Value[] plain = [.. values.Select(static value => ValueOf(value))];
			Pairs = [.. plain.Select(vx => plain.Select(vy => ProductsOf(vx, vy)).ToArray())];
			Elements = [.. plain.Select(vx => ResultsOf(vx, random))];
		}

		internal List<SM9Fp12> Values { get; }

		internal PairProducts[][] Pairs { get; }

		internal ElementResults[] Elements { get; }

		private static PairProducts ProductsOf(Fp12Value vx, Fp12Value vy)
		{
			Fp12Value normalized = new([vy.C[0], Fp2Value.Zero, vy.C[2], Fp2Value.One, Fp2Value.Zero, Fp2Value.Zero]);
			Fp12Value pair = normalized * new Fp12Value([vy.C[1], Fp2Value.Zero, vy.C[5], Fp2Value.One, Fp2Value.Zero, Fp2Value.Zero]);
			return new PairProducts(vx * vy, vx * new Fp12Value([vy.C[0], Fp2Value.Zero, vy.C[2], vy.C[3], Fp2Value.Zero, Fp2Value.Zero]), vx * normalized, pair, vx * pair);
		}

		private static ElementResults ResultsOf(Fp12Value vx, Random random)
		{
			Fp12Value line = new([RandomFp2(random), Fp2Value.Zero, RandomFp2(random), RandomFp2(random), Fp2Value.Zero, Fp2Value.Zero]);
			return new ElementResults(vx, vx * vx, CyclotomicFormula(vx), vx.Pow(P), vx.Pow(P * P), vx.Pow(P * P * P), new Fp12Value(vx.C.Select(static (coefficient, i) => i % 2 is 0 ? coefficient : -coefficient).ToArray()), Element(line), vx * line);
		}
	}

	private sealed class Operations(OperationCases cases) : ISM9LanesVisitor<List<string>>
	{
		public List<string> Visit<TVector>() where TVector : unmanaged, ISM9Vector<TVector>
		{
			List<string> failures = [];
			SM9LaneScratch scratch = default;
			SM9Fp12Lanes a = default;
			SM9Fp12Lanes b = default;
			SM9Fp12Lanes c = default;
			ulong[] batch = new ulong[SM9Lanes<TVector>.LineBatchLength];
			ulong[] otherBatch = new ulong[SM9Lanes<TVector>.LineBatchLength];
			ulong[] pairs = new ulong[SM9Lanes<TVector>.PairBatchLength];

			for (int i = 0; i < cases.Values.Count; ++i)
			{
				SM9Fp12 x = cases.Values[i];
				OperationCases.ElementResults results = cases.Elements[i];
				Fp12Value vx = results.Value;
				SM9Lanes<TVector>.FromFp12(in x, ref a);
				SM9Lanes<TVector>.ToFp12(ref a, out SM9Fp12 back);

				if (!LimbsOf(back.C0.C0.A0).SequenceEqual(LimbsOf(x.C0.C0.A0)) || ValueOf(back) != vx)
				{
					failures.Add($"Round trip {vx}");
				}

				for (int j = 0; j < cases.Values.Count; ++j)
				{
					SM9Fp12 y = cases.Values[j];
					OperationCases.PairProducts products = cases.Pairs[i][j];
					SM9Lanes<TVector>.FromFp12(in x, ref a);
					SM9Lanes<TVector>.FromFp12(in y, ref b);
					SM9Lanes<TVector>.Multiply(ref a, ref b, ref c, ref scratch);
					Check(failures, "Multiply", Out<TVector>(ref c), products.Product);
					SM9Lanes<TVector>.FromLine(in y.C0.C0, in y.C0.C1, in y.C1.C1, ref b);
					SM9Lanes<TVector>.MultiplyByLine(ref a, ref b, ref c, ref scratch);
					Check(failures, "MultiplyByLine", Out<TVector>(ref c), products.ByLine);
					// A line of a batch with α = β = 1, so l0 = A and l2 = B, in the last lane of the batch.
					SM9PrecomputedLine[] lines = new SM9PrecomputedLine[SM9Lanes<TVector>.BatchLines];
					lines[^1] = new SM9PrecomputedLine { A = y.C0.C0, B = y.C0.C1 };
					SM9Lanes<TVector>.SplitFactors(in SM9Fp.One, in SM9Fp.One, ref batch[0]);
					SM9Lanes<TVector>.EvaluateLines(lines, ref batch[0], ref scratch);
					SM9Lanes<TVector>.MultiplyByNormalizedLine(ref a, ref batch[0], lines.Length - 1, ref c, ref scratch);
					Check(failures, "MultiplyByNormalizedLine", Out<TVector>(ref c), products.ByNormalizedLine);
					// The product of that line and another, l0′ = A′ and l2′ = B′ from the coefficients of w and w⁵ of y, in the last lane of the batches.
					SM9PrecomputedLine[] otherLines = new SM9PrecomputedLine[SM9Lanes<TVector>.BatchLines];
					otherLines[^1] = new SM9PrecomputedLine { A = y.C1.C0, B = y.C1.C2 };
					SM9Lanes<TVector>.SplitFactors(in SM9Fp.One, in SM9Fp.One, ref otherBatch[0]);
					SM9Lanes<TVector>.EvaluateLines(otherLines, ref otherBatch[0], ref scratch);
					SM9Lanes<TVector>.EvaluateLinePairs(ref batch[0], ref otherBatch[0], ref pairs[0], ref scratch);
					SM9Lanes<TVector>.FromLinePair(ref pairs[0], lines.Length - 1, ref c);
					Check(failures, "FromLinePair", Out<TVector>(ref c), products.LinePair);
					SM9Lanes<TVector>.MultiplyByLinePair(ref a, ref pairs[0], lines.Length - 1, ref c, ref scratch);
					Check(failures, "MultiplyByLinePair", Out<TVector>(ref c), products.ByLinePair);
				}

				SM9Lanes<TVector>.FromFp12(in x, ref a);
				SM9Lanes<TVector>.Square(ref a, ref c, ref scratch);
				Check(failures, "Square", Out<TVector>(ref c), results.Square);
				SM9Lanes<TVector>.CyclotomicSquare(ref a, ref c, ref scratch);
				Check(failures, "CyclotomicSquare formula", Out<TVector>(ref c), results.Cyclotomic);
				SM9Lanes<TVector>.Frobenius(ref a, ref c, ref scratch);
				Check(failures, "Frobenius", Out<TVector>(ref c), results.Frobenius);
				SM9Lanes<TVector>.FrobeniusSquared(ref a, ref c, ref scratch);
				Check(failures, "FrobeniusSquared", Out<TVector>(ref c), results.FrobeniusSquared);
				SM9Lanes<TVector>.FrobeniusCubed(ref a, ref c, ref scratch);
				Check(failures, "FrobeniusCubed", Out<TVector>(ref c), results.FrobeniusCubed);
				SM9Lanes<TVector>.Conjugate(ulong.MaxValue, ref a, ref c);
				Check(failures, "Conjugate", Out<TVector>(ref c), results.Conjugate);
				SM9Lanes<TVector>.Conjugate(0, ref a, ref c);
				Check(failures, "Conjugate not", Out<TVector>(ref c), vx);

				// Results may be inputs.
				SM9Lanes<TVector>.Multiply(ref a, ref a, ref a, ref scratch);
				Check(failures, "Multiply aliased", Out<TVector>(ref a), results.Square);
				SM9Lanes<TVector>.FromFp12(in x, ref a);
				SM9Fp12 lineElement = results.Line;
				SM9Lanes<TVector>.FromLine(in lineElement.C0.C0, in lineElement.C0.C1, in lineElement.C1.C1, ref b);
				SM9Lanes<TVector>.MultiplyByLine(ref a, ref b, ref a, ref scratch);
				Check(failures, "MultiplyByLine aliased", Out<TVector>(ref a), results.ByLine);
				SM9Lanes<TVector>.FromFp12(in x, ref a);
				SM9Lanes<TVector>.CyclotomicSquare(ref a, ref a, ref scratch);
				Check(failures, "CyclotomicSquare aliased", Out<TVector>(ref a), results.Cyclotomic);
				SM9Lanes<TVector>.FromFp12(in x, ref a);
				SM9Lanes<TVector>.Frobenius(ref a, ref a, ref scratch);
				Check(failures, "Frobenius aliased", Out<TVector>(ref a), results.Frobenius);
				SM9Lanes<TVector>.FromFp12(in x, ref a);
				SM9Lanes<TVector>.Conjugate(ulong.MaxValue, ref a, ref a);
				Check(failures, "Conjugate aliased", Out<TVector>(ref a), results.Conjugate);
			}

			return failures;
		}

		private static SM9Fp12 Out<TVector>(ref SM9Fp12Lanes value) where TVector : unmanaged, ISM9Vector<TVector>
		{
			SM9Lanes<TVector>.ToFp12(ref value, out SM9Fp12 result);
			return result;
		}
	}

	private sealed class DoublingSteps(SM9AffinePoint<SM9Fp> p, SM9AffinePoint<SM9Fp2> q, G2Value expected) : ISM9LanesVisitor<List<string>>
	{
		public List<string> Visit<TVector>() where TVector : unmanaged, ISM9Vector<TVector>
		{
			List<string> failures = [];
			SM9Fp.Negate(in p.X, out SM9Fp negatedX);
			SM9LaneScratch scratch = default;
			SM9Fp12Lanes point = default;
			SM9Fp12Lanes factors = default;
			SM9Fp12Lanes line = default;
			SM9Point<SM9Fp2> t = new() { X = q.X, Y = q.Y, Z = SM9Fp2.One };
			SM9Point<SM9Fp2> scalar = t;
			SM9Lanes<TVector>.FromPoint(in t, ref point);
			SM9Lanes<TVector>.FromFactors(in negatedX, in p.Y, ref factors);

			for (int k = 0; k < 2; ++k)
			{
				SM9Lanes<TVector>.DoublingStep(ref point, ref factors, ref line, ref scratch);
				SM9MillerLoop.DoublingStep(ref scalar, out SM9Line expectedLine);

				// l0 may be up to 4.0001p with limbs above 2^26, which MultiplyByLine takes but SM9Fp cannot hold, so the line is reduced first.
				SM9Lanes<TVector>.WeakReduce(ref line);
				SM9Lanes<TVector>.ToFp12(ref line, out SM9Fp12 actual);
				SM9Fp2.MultiplyByFp(in expectedLine.L2, in negatedX, out SM9Fp2 l2);
				SM9Fp2.MultiplyByFp(in expectedLine.L3, in p.Y, out SM9Fp2 l3);
				Fp12Value reference = new([ValueOf(expectedLine.L0), Fp2Value.Zero, ValueOf(l2), ValueOf(l3), Fp2Value.Zero, Fp2Value.Zero]);

				if (!IsReduced(actual) || ValueOf(actual) != reference)
				{
					failures.Add($"line {k} gave {ValueOf(actual)}, expected {reference}");
				}
			}

			SM9Lanes<TVector>.ToPoint(ref point, out t);

			if (!IsReduced(t.X) || !IsReduced(t.Y) || !IsReduced(t.Z) || ValueOf(t) != expected)
			{
				failures.Add($"4Q gave {ValueOf(t)}, expected {expected}");
			}

			return failures;
		}
	}

	// The formulas of SM9MillerLoop's doubling step: with A = XY, B = Y², C = Z², E = 3b'·C, F = 3E and H = 2YZ, 2T = (2A(B − F) : (B + F)² − 12E² : 4BH) and the line (B − E, 3X²·(−xP), H·yP).
	private sealed class ExtremeDoubling(SM9Point<SM9Fp2> t, SM9Fp negatedX, SM9Fp y, SM9Fp12 f) : ISM9LanesVisitor<List<string>>
	{
		public List<string> Visit<TVector>() where TVector : unmanaged, ISM9Vector<TVector>
		{
			List<string> failures = [];
			Fp2Value x0 = ValueOf(t.X);
			Fp2Value y0 = ValueOf(t.Y);
			Fp2Value z0 = ValueOf(t.Z);
			Fp2Value a = x0 * y0;
			Fp2Value b = y0 * y0;
			Fp2Value e = z0 * z0 * TwistB * 3;
			Fp2Value h = y0 * z0 * 2;
			Fp2Value expectedX = a * (b - e * 3) * 2;
			Fp2Value expectedY = (b + e * 3) * (b + e * 3) - e * e * 12;
			Fp2Value expectedZ = b * h * 4;
			Fp12Value line = new([b - e, Fp2Value.Zero, x0 * x0 * 3 * ValueOf(negatedX), h * ValueOf(y), Fp2Value.Zero, Fp2Value.Zero]);
			SM9LaneScratch scratch = default;
			SM9Fp12Lanes point = default;
			SM9Fp12Lanes factors = default;
			SM9Fp12Lanes lanes = default;
			SM9Fp12Lanes element = default;
			SM9Lanes<TVector>.FromPoint(in t, ref point);
			SM9Lanes<TVector>.FromFactors(in negatedX, in y, ref factors);
			SM9Lanes<TVector>.DoublingStep(ref point, ref factors, ref lanes, ref scratch);
			SM9Lanes<TVector>.FromFp12(in f, ref element);
			SM9Lanes<TVector>.MultiplyByLine(ref element, ref lanes, ref element, ref scratch);
			SM9Lanes<TVector>.ToFp12(ref element, out SM9Fp12 product);
			Check(failures, "MultiplyByLine of the doubling line", product, ValueOf(f) * line);
			SM9Lanes<TVector>.WeakReduce(ref lanes);
			SM9Lanes<TVector>.ToFp12(ref lanes, out SM9Fp12 actual);
			Check(failures, "doubling line", actual, line);
			SM9Lanes<TVector>.ToPoint(ref point, out SM9Point<SM9Fp2> doubled);

			if (!IsReduced(doubled.X) || !IsReduced(doubled.Y) || !IsReduced(doubled.Z) || ValueOf(doubled.X) != expectedX || ValueOf(doubled.Y) != expectedY || ValueOf(doubled.Z) != expectedZ)
			{
				failures.Add($"2T of ({x0}, {y0}, {z0})");
			}

			return failures;
		}
	}

	private sealed class CyclotomicFormulas(List<SM9Fp12> values) : ISM9LanesVisitor<List<string>>
	{
		public List<string> Visit<TVector>() where TVector : unmanaged, ISM9Vector<TVector>
		{
			List<string> failures = [];
			SM9LaneScratch scratch = default;
			SM9Fp12Lanes a = default;
			SM9Fp12Lanes c = default;

			foreach (SM9Fp12 x in values)
			{
				Fp12Value expected = CyclotomicFormula(ValueOf(x));
				SM9Lanes<TVector>.FromFp12(in x, ref a);
				SM9Lanes<TVector>.CyclotomicSquare(ref a, ref c, ref scratch);
				SM9Lanes<TVector>.ToFp12(ref c, out SM9Fp12 square);
				Check(failures, "CyclotomicSquare formula", square, expected);
				SM9Lanes<TVector>.CyclotomicSquare(ref a, ref a, ref scratch);
				SM9Lanes<TVector>.ToFp12(ref a, out square);
				Check(failures, "CyclotomicSquare aliased", square, expected);
			}

			return failures;
		}
	}

	private sealed class CyclotomicSquares((SM9Fp12 Element, Fp12Value Square)[] values) : ISM9LanesVisitor<List<string>>
	{
		public List<string> Visit<TVector>() where TVector : unmanaged, ISM9Vector<TVector>
		{
			List<string> failures = [];
			SM9LaneScratch scratch = default;
			SM9Fp12Lanes a = default;
			SM9Fp12Lanes c = default;

			foreach ((SM9Fp12 element, Fp12Value expected) in values)
			{
				SM9Lanes<TVector>.FromFp12(in element, ref a);
				SM9Lanes<TVector>.CyclotomicSquare(ref a, ref c, ref scratch);
				SM9Lanes<TVector>.ToFp12(ref c, out SM9Fp12 square);
				Check(failures, "CyclotomicSquare", square, expected);
			}

			return failures;
		}
	}
}
