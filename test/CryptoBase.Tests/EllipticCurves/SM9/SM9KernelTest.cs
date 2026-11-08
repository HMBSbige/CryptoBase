using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.SM9;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9Reference;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9TestUtils;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9Vectors;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.EllipticCurves.SM9;

public class SM9KernelTest
{
	private const int RandomCount = 6;

	private static readonly BigInteger Lambda = Parse("1E600000005474DE26804E46A9A65C91E2BF5F68BCD8990E5");

	// What the reference gives for the tests below, once for all the kernels.
	private static readonly Lazy<(SM9AffinePoint<SM9Fp> P, SM9AffinePoint<SM9Fp> Other, SM9AffinePoint<SM9Fp2> Q, SM9AffinePoint<SM9Fp2> OtherQ)[]> ProductPairs = new(ComputeProductPairs);

	private static readonly Lazy<(SM9AffinePoint<SM9Fp> Scaled, SM9AffinePoint<SM9Fp> Shifted)> SignaturePoints = new(static () => (Element(Multiply(SM9PairingTest.Signature, Parse(VerifyH1))!), Element(Add(SM9PairingTest.Signature, Multiply(P1, Parse(SignH)))!)));

	private static readonly Lazy<(BigInteger A, BigInteger B, SM9AffinePoint<SM9Fp> P, SM9AffinePoint<SM9Fp2> Q)[]> BilinearCases = new(ComputeBilinearCases);

	private static readonly Lazy<PowerCases> Powers = new(ComputePowerCases);

	private static readonly Lazy<G1Cases> G1Products = new(ComputeG1Cases);

	private static readonly Lazy<(SM9Point<SM9Fp2> Addend, (BigInteger K, G2Value? Product, G2Value? Sum)[] Products)> G2Products = new(ComputeG2Products);

	private static readonly Lazy<(G2Value Point, SM9Point<SM9Fp2> Projective, G2Value? Product)[]> LoopProducts = new(ComputeLoopProducts);

	private static readonly Lazy<(G2Value[] Values, SM9Point<SM9Fp2>[] Points)> AffineCases = new(ComputeAffineCases);

	private sealed record PowerCases(SM9AffinePoint<SM9Fp> Point, Fp12Value Pairing, (BigInteger K, Fp12Value Power)[] Products);

	private sealed record G1Cases(SM9AffinePoint<SM9Fp> Point, SM9Point<SM9Fp> Addend, SM9BaseTable<SM9Fp> Table, SM9BaseTable<SM9Fp> SecretTable, (BigInteger K, G1Value? Base, G1Value? Product, G1Value? Sum, G1Value? AddendSum)[] Products, SM9Point<SM9Fp> Negated, SM9BaseTable<SM9Fp> MultipleTable);

	// Scalars at the edges of the windows, of the parts of the decompositions and of the range, with random ones.
	internal static List<BigInteger> Scalars(Random random, int count)
	{
		List<BigInteger> scalars = [1, 2, 3, 4, 15, 16, 17, 31, 32, 33, N - 1, N - 2, N - 3, N - 16, (N - 1) / 2, (N + 1) / 2, Lambda, N - Lambda, ModN(Lambda * Lambda), P % N, ModN(P * P), ModN(P * P * P), (BigInteger.One << 255) - 1, BigInteger.One << 255, (BigInteger.One << 127) - 1, BigInteger.One << 128, ModN(Parse("8421084210842108421084210842108421084210842108421084210842108421"))];

		for (int i = 0; i < count; ++i)
		{
			scalars.Add(RandomBelow(random, N - 1) + 1);
		}

		return scalars;
	}

	[Test]
	public async Task EveryKernelIsListed()
	{
		await Assert.That(SM9KernelCase.All().Select(static kernel => kernel.KernelType)).IsEquivalentTo(ImplementationsOf(typeof(ISM9Kernel)));
	}

	[Test]
	[MethodDataSource(typeof(SM9KernelCase), nameof(SM9KernelCase.All))]
	public async Task PairingsGiveTheExamples(SM9KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];
		SM9PrecomputedLine[] lines = new SM9PrecomputedLine[SM9MillerLoop.LineCount];

		foreach (Func<(G1Value P, G2Value Q, string Expected)> example in SM9PairingTest.Examples())
		{
			(G1Value p, G2Value q, string expected) = example();
			SM9AffinePoint<SM9Fp> ep = Element(p);
			SM9AffinePoint<SM9Fp2> eq = Element(q);
			kernel.MillerLoop(in ep, in eq, out SM9Fp12 f);
			kernel.FinalExponentiation(in f, out SM9Fp12 direct);
			SM9MillerLoop.Precompute(in eq, lines);
			kernel.MillerLoop(in ep, lines, out f);
			kernel.FinalExponentiation(in f, out SM9Fp12 precomputed);

			if (ValueOf(direct).ToHex() != expected || ValueOf(precomputed).ToHex() != expected)
			{
				failures.Add(expected[..16]);
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The final exponentiation of each kernel against that of SM9FinalExponentiation, which SM9PairingTest checks against the plain power: on random elements, on elements of Fp6, whose conjugates are themselves, on elements with C0 = 0, on 1 and on coefficients of extreme raw values.
	[Test]
	[MethodDataSource(typeof(SM9KernelCase), nameof(SM9KernelCase.All))]
	public async Task FinalExponentiationsMatchTheScalarOne(SM9KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(9);
		SM9Fp largest = Raw(ReducedBound - 1);
		SM9Fp2 extreme = new() { A0 = largest, A1 = Raw(P - 1) };
		List<SM9Fp12> values = [Element(Fp12Value.One)];

		for (int i = 0; i < 3; ++i)
		{
			Fp12Value f = RandomFp12(random);
			values.Add(Element(f));
			values.Add(Element(new Fp12Value([f.C[0], Fp2Value.Zero, f.C[2], Fp2Value.Zero, f.C[4], Fp2Value.Zero])));
			values.Add(Element(new Fp12Value([Fp2Value.Zero, f.C[1], Fp2Value.Zero, f.C[3], Fp2Value.Zero, f.C[5]])));
		}

		values.Add(new SM9Fp12 { C0 = new SM9Fp6 { C0 = extreme, C1 = extreme, C2 = extreme }, C1 = new SM9Fp6 { C0 = extreme, C1 = extreme, C2 = extreme } });
		List<string> failures = [];

		foreach (SM9Fp12 value in values)
		{
			kernel.FinalExponentiation(in value, out SM9Fp12 actual);
			SM9FinalExponentiation.Run(in value, out SM9Fp12 expected);

			if (ValueOf(actual) != ValueOf(expected) || !IsReduced(actual))
			{
				failures.Add($"{ValueOf(value)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The product of two Miller loops with lines gives e(P, Q)·e(P', Q') after the final exponentiation: for random points, the product of the two pairings, and for the verification of GM/T 0044.5 A.2, e([h1]S, P2)·e(S + [h]P1, Ppub-s) = e(S, [h1]P2 + Ppub-s)·g^h = u·t, the w of the signature.
	[Test]
	[MethodDataSource(typeof(SM9KernelCase), nameof(SM9KernelCase.All))]
	public async Task PairingProductsMatchTheirFactors(SM9KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];
		SM9PrecomputedLine[] lines = new SM9PrecomputedLine[SM9MillerLoop.LineCount];
		SM9PrecomputedLine[] otherLines = new SM9PrecomputedLine[SM9MillerLoop.LineCount];

		for (int i = 0; i < ProductPairs.Value.Length; ++i)
		{
			(SM9AffinePoint<SM9Fp> p, SM9AffinePoint<SM9Fp> other, SM9AffinePoint<SM9Fp2> q, SM9AffinePoint<SM9Fp2> otherQ) = ProductPairs.Value[i];
			SM9MillerLoop.Precompute(in q, lines);
			SM9MillerLoop.Precompute(in otherQ, otherLines);
			kernel.MillerLoop(in p, lines, in other, otherLines, out SM9Fp12 f);
			kernel.FinalExponentiation(in f, out SM9Fp12 product);
			SM9Fp12 first = Pair(kernel, in p, in q);
			SM9Fp12 second = Pair(kernel, in other, in otherQ);
			SM9Fp12.Multiply(in first, in second, out SM9Fp12 expected);

			if (ValueOf(product) != ValueOf(expected) || !IsReduced(product))
			{
				failures.Add($"product {i}");
			}
		}

		(SM9AffinePoint<SM9Fp> scaled, SM9AffinePoint<SM9Fp> shifted) = SignaturePoints.Value;
		SM9MillerLoop.Precompute(in SM9G2.Generator, lines);
		SM9AffinePoint<SM9Fp2> signPublic = Element(SM9PairingTest.SignPublic);
		SM9MillerLoop.Precompute(in signPublic, otherLines);
		kernel.MillerLoop(in scaled, lines, in shifted, otherLines, out SM9Fp12 g);
		kernel.FinalExponentiation(in g, out SM9Fp12 w);

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(ValueOf(w).ToHex()).IsEqualTo(SignW);
		}
	}

	// e([a]P1, [b]P2) = e(P1, P2)^(ab), and e(P1, P2) ≠ 1 has order N.
	[Test]
	[MethodDataSource(typeof(SM9KernelCase), nameof(SM9KernelCase.All))]
	public async Task PairingIsBilinearAndNonDegenerate(SM9KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		SM9Fp12 g = Pair(kernel, Element(P1), Element(P2));
		List<string> failures = [];

		foreach ((BigInteger a, BigInteger b, SM9AffinePoint<SM9Fp> p, SM9AffinePoint<SM9Fp2> q) in BilinearCases.Value)
		{
			SM9Fp12 e = Pair(kernel, in p, in q);
			FieldElement<SM9Order> ab = Scalar(a * b);
			kernel.Power(in g, in ab, out SM9Fp12 expected);

			if (ValueOf(e) != ValueOf(expected))
			{
				failures.Add($"{a:X}, {b:X}");
			}
		}

		FieldElement<SM9Order> orderMinusOne = Scalar(N - 1);
		kernel.Power(in g, in orderMinusOne, out SM9Fp12 inverse);
		SM9Fp12.Multiply(in inverse, in g, out SM9Fp12 one);

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(ValueOf(g)).IsNotEqualTo(Fp12Value.One);
			await Assert.That(ValueOf(one)).IsEqualTo(Fp12Value.One);
		}
	}

	// The powers of GM/T 0044.5: w = g^r and t = g^h of the signature, g1 = e(Ppub-e, P2)^rA, g2 = e(Ppub-e, P2)^rB and g3 = g1^rB of the key exchange, and w = g^r of the encapsulation and the encryption.
	[Test]
	[MethodDataSource(typeof(SM9KernelCase), nameof(SM9KernelCase.All))]
	public async Task PowersGiveTheExamples(SM9KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];
		SM9Fp12 exchangeBase = Pair(kernel, Element(G1(ExchangePublicX, ExchangePublicY)), Element(P2));
		(string Base, string Exponent, string Expected)[] cases =
		[
			(SignG, SignR, SignW),
			(SignG, SignH, VerifyT),
			(ValueOfHex(exchangeBase), ExchangeRA, ExchangeG1),
			(ValueOfHex(exchangeBase), ExchangeRB, ExchangeG2),
			(ExchangeG1, ExchangeRB, ExchangeG3),
			(EncryptG, EncapsulateR, EncapsulateW),
			(EncryptG, EncryptR, EncryptW),
		];

		foreach ((string baseHex, string exponentHex, string expected) in cases)
		{
			SM9Fp12 value = Element(Fp12Value.FromHex(baseHex));
			FieldElement<SM9Order> exponent = Scalar(Parse(exponentHex));
			SM9Fp12[] table = new SM9Fp12[SM9GTPower.FixedTableLength];
			SM9GTPower.BuildFixedTable(in value, table, out SM9Fp12 inverse);
			SM9Fp12[] kernelTable = new SM9Fp12[SM9GTPower.FixedTableLength];
			kernel.BuildPowerTable(in value, kernelTable, out SM9Fp12 kernelInverse);
			kernel.Power(in value, in exponent, out SM9Fp12 power);
			kernel.Power(table, in inverse, in exponent, out SM9Fp12 fixedPower);
			kernel.Power(kernelTable, in kernelInverse, in exponent, out SM9Fp12 kernelPower);

			foreach ((string name, SM9Fp12 actual) in (List<(string, SM9Fp12)>)[("Power", power), ("fixed Power", fixedPower), ("Power of the kernel table", kernelPower)])
			{
				if (ValueOf(actual).ToHex() != expected || !IsReduced(actual))
				{
					failures.Add($"{name} {expected[..16]}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(SM9KernelCase), nameof(SM9KernelCase.All))]
	public async Task PowersMatchTheReference(SM9KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		PowerCases cases = Powers.Value;
		SM9AffinePoint<SM9Fp> point = cases.Point;
		SM9Fp12 value = Pair(kernel, in point, Element(P2));
		SM9Fp12[] table = new SM9Fp12[SM9GTPower.FixedTableLength];
		SM9GTPower.BuildFixedTable(in value, table, out SM9Fp12 inverse);
		SM9Fp12[] kernelTable = new SM9Fp12[SM9GTPower.FixedTableLength];
		kernel.BuildPowerTable(in value, kernelTable, out SM9Fp12 kernelInverse);
		List<string> failures = [];

		if (ValueOf(value) != cases.Pairing)
		{
			failures.Add("pairing");
		}

		// The kernel builds the entries of the scalar table, as values.
		for (int i = 0; i < table.Length; ++i)
		{
			if (ValueOf(kernelTable[i]) != ValueOf(table[i]) || !IsReduced(kernelTable[i]))
			{
				failures.Add($"entry {i}");
			}
		}

		if (ValueOf(kernelInverse) != ValueOf(inverse))
		{
			failures.Add("inverse");
		}

		foreach ((BigInteger k, Fp12Value expected) in cases.Products)
		{
			FieldElement<SM9Order> exponent = Scalar(k);
			kernel.Power(in value, in exponent, out SM9Fp12 power);
			kernel.Power(table, in inverse, in exponent, out SM9Fp12 fixedPower);
			kernel.Power(kernelTable, in kernelInverse, in exponent, out SM9Fp12 kernelPower);

			if (ValueOf(power) != expected || ValueOf(fixedPower) != expected || ValueOf(kernelPower) != expected)
			{
				failures.Add($"{k:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(SM9KernelCase), nameof(SM9KernelCase.All))]
	public async Task G1ProductsMatchTheReference(SM9KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		G1Cases cases = G1Products.Value;
		SM9AffinePoint<SM9Fp> ePoint = cases.Point;
		SM9Point<SM9Fp> eAddend = cases.Addend;
		SM9BaseTable<SM9Fp> table = cases.Table;
		SM9BaseTable<SM9Fp> secretTable = cases.SecretTable;
		List<string> failures = [];

		foreach ((BigInteger k, G1Value? expectedBase, G1Value? expected, G1Value? expectedSum, G1Value? addendSum) in cases.Products)
		{
			FieldElement<SM9Order> scalar = Scalar(k);
			FieldElement<SM9Order> other = Scalar(ModN(k * 3 + 1));
			kernel.MultiplyBaseG1(SM9G1Group.BaseTable, in scalar, out SM9Point<SM9Fp> baseProduct);
			kernel.MultiplyBaseG1(table, in scalar, out SM9Point<SM9Fp> tableProduct);
			kernel.MultiplyBaseG1(secretTable, in scalar, out SM9Point<SM9Fp> secretProduct);
			kernel.MultiplyBaseSumG1(SM9G1Group.BaseTable, in other, table, in scalar, out SM9Point<SM9Fp> baseSum);
			kernel.MultiplyBaseSumG1(secretTable, in scalar, SM9G1Group.BaseTable, in other, out SM9Point<SM9Fp> secretSum);
			kernel.MultiplyG1(in ePoint, in scalar, out SM9Point<SM9Fp> product);
			kernel.MultiplyVariableTimeG1(in ePoint, in scalar, out SM9Point<SM9Fp> variableTimeProduct);
			kernel.MultiplyBaseAddVariableTimeG1(in scalar, in eAddend, out SM9Point<SM9Fp> sum);

			if (ValueOf(baseProduct) != expectedBase || ValueOf(tableProduct) != expected || ValueOf(secretProduct) != expected || ValueOf(baseSum) != expectedSum || ValueOf(secretSum) != expectedSum || ValueOf(product) != expected || ValueOf(variableTimeProduct) != expected || ValueOf(sum) != addendSum)
			{
				failures.Add($"{k:X}");
			}
		}

		// The sums may be the point at infinity: 5·P1 − 5·P1, and a·P1 + b·Q for Q = λP1 and a = −bλ.
		SM9Point<SM9Fp> negated = cases.Negated;
		FieldElement<SM9Order> five = Scalar(5);
		kernel.MultiplyBaseAddVariableTimeG1(in five, in negated, out SM9Point<SM9Fp> infinity);
		SM9BaseTable<SM9Fp> multipleTable = cases.MultipleTable;
		FieldElement<SM9Order> opposite = Scalar(ModN(-5 * Lambda));
		kernel.MultiplyBaseSumG1(SM9G1Group.BaseTable, in opposite, multipleTable, in five, out SM9Point<SM9Fp> infiniteSum);

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(ValueOf(infinity)).IsNull();
			await Assert.That(ValueOf(infiniteSum)).IsNull();
		}
	}

	[Test]
	[MethodDataSource(typeof(SM9KernelCase), nameof(SM9KernelCase.All))]
	public async Task G2ProductsMatchTheReference(SM9KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		(SM9Point<SM9Fp2> eAddend, (BigInteger K, G2Value? Product, G2Value? Sum)[] products) = G2Products.Value;
		List<string> failures = [];

		foreach ((BigInteger k, G2Value? expected, G2Value? expectedSum) in products)
		{
			FieldElement<SM9Order> scalar = Scalar(k);
			kernel.MultiplyBaseG2(in scalar, out SM9Point<SM9Fp2> baseProduct);
			kernel.MultiplyBaseAddVariableTimeG2(in scalar, in eAddend, out SM9Point<SM9Fp2> sum);

			if (ValueOf(baseProduct) != expected || ValueOf(sum) != expectedSum)
			{
				failures.Add($"{k:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// [6t + 2]Q of the subgroup check for points of G2 and for points of the twist outside it, in projective forms with Z other than 1, against the reference.
	[Test]
	[MethodDataSource(typeof(SM9KernelCase), nameof(SM9KernelCase.All))]
	public async Task LoopScalarProductsMatchTheReference(SM9KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];

		foreach ((G2Value point, SM9Point<SM9Fp2> projective, G2Value? expected) in LoopProducts.Value)
		{
			kernel.MultiplyByLoopScalarG2(in projective, out SM9Point<SM9Fp2> product);

			if (ValueOf(product) != expected)
			{
				failures.Add($"{point}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The tables of a point of G1 and of one of G2 for the widths 4, 5 and 6, whose 65, 52 and 43 windows fill the last round of lanes or leave some of it, public and secret, entry by entry against those of the scalar kernel, whose first and last windows hold j·2^(wi)·G as the reference has it.
	[Test]
	[MethodDataSource(typeof(SM9KernelCase), nameof(SM9KernelCase.All))]
	public async Task BaseTablesMatchTheReference(SM9KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(9);
		G1Value point = Multiply(P1, RandomBelow(random, N - 1) + 1)!;
		G2Value otherPoint = Multiply(P2, RandomBelow(random, N - 1) + 1)!;
		SM9AffinePoint<SM9Fp> ePoint = Element(point);
		SM9AffinePoint<SM9Fp2> eOtherPoint = Element(otherPoint);
		List<string> failures = [];

		foreach (int width in (int[])[4, 5, 6])
		{
			int windowLength = 1 << width - 1;
			int windows = SM9Windows.DigitCount(SM9Order.BitLength, width);
			bool againstReference = kernel.KernelType == typeof(SM9Scalar);
			G1Value?[] firstG1 = againstReference ? WindowMultiples(point, windowLength, Add) : [];
			G2Value?[] firstG2 = againstReference ? WindowMultiples(otherPoint, windowLength, Add) : [];
			G1Value?[] lastG1 = againstReference ? WindowMultiples(Multiply(point, ModN(BigInteger.One << width * (windows - 1))), windowLength, Add) : [];
			G2Value?[] lastG2 = againstReference ? WindowMultiples(Multiply(otherPoint, ModN(BigInteger.One << width * (windows - 1))), windowLength, Add) : [];

			foreach (bool secret in (bool[])[false, true])
			{
				SM9AffinePoint<SM9Fp>[] entries = new SM9AffinePoint<SM9Fp>[windows * windowLength];
				SM9AffinePoint<SM9Fp>[] expected = new SM9AffinePoint<SM9Fp>[entries.Length];
				kernel.BuildBaseTable(in ePoint, width, secret, entries);
				SM9Scalar.BuildBaseTable(in ePoint, width, secret, expected);
				SM9AffinePoint<SM9Fp2>[] otherEntries = new SM9AffinePoint<SM9Fp2>[entries.Length];
				SM9AffinePoint<SM9Fp2>[] otherExpected = new SM9AffinePoint<SM9Fp2>[entries.Length];
				kernel.BuildBaseTable(in eOtherPoint, width, secret, otherEntries);
				SM9Scalar.BuildBaseTable(in eOtherPoint, width, secret, otherExpected);

				for (int e = 0; e < entries.Length; ++e)
				{
					int i = e / windowLength;
					int j = e % windowLength;

					if (ValueOf(entries[e]) != ValueOf(expected[e]) || ValueOf(otherEntries[e]) != ValueOf(otherExpected[e]) || !IsReduced(entries[e].X) || !IsReduced(entries[e].Y) || !IsReduced(otherEntries[e].X) || !IsReduced(otherEntries[e].Y))
					{
						failures.Add($"width {width}, secret {secret}, entry {e}");
					}
					else if (againstReference && (i is 0 || i == windows - 1) && (ValueOf(entries[e]) != (i is 0 ? firstG1 : lastG1)[j] || ValueOf(otherEntries[e]) != (i is 0 ? firstG2 : lastG2)[j]))
					{
						failures.Add($"width {width}, secret {secret}, entry {e} against the reference");
					}
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Affine forms of points of G2 with random Z, as many as the lines of a pairing and a few, in variable and in constant time, against the reference.
	[Test]
	[MethodDataSource(typeof(SM9KernelCase), nameof(SM9KernelCase.All))]
	public async Task AffineFormsMatchTheReference(SM9KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		(G2Value[] values, SM9Point<SM9Fp2>[] points) = AffineCases.Value;
		List<string> failures = [];

		foreach (int count in (int[])[1, 9, SM9MillerLoop.LineCount])
		{
			foreach (bool variableTime in (bool[])[false, true])
			{
				SM9AffinePoint<SM9Fp2>[] result = new SM9AffinePoint<SM9Fp2>[count];
				kernel.ToAffine(points.AsSpan(0, count), result, variableTime);

				for (int i = 0; i < count; ++i)
				{
					if (ValueOf(result[i]) != values[i] || !IsReduced(result[i].X) || !IsReduced(result[i].Y))
					{
						failures.Add($"{count} points, variable time {variableTime}, point {i}");
					}
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The points of GM/T 0044.5: Ppub-s = [ks]P2, dsA = [t2]P1, S = [l]dsA and P = [h1]P2 + Ppub-s of the signature; Ppub-e = [ke]P1, deA = [t2]P2, deB = [t4]P2, QB = [h1]P1 + Ppub-e, RA = [rA]QB and RB = [rB]QA of the key exchange; Ppub-e, deB, QB and C = [r]QB of the encapsulation, and C1 of the encryption.
	[Test]
	[MethodDataSource(typeof(SM9KernelCase), nameof(SM9KernelCase.All))]
	public async Task ProductsGiveTheExamples(SM9KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		G1Value signKey = G1(SignKeyX, SignKeyY);
		G1Value exchangePublic = G1(ExchangePublicX, ExchangePublicY);
		G1Value encryptPublic = G1(EncryptPublicX, EncryptPublicY);
		G1Value exchangeQB = G1(ExchangeQBX, ExchangeQBY);
		G1Value exchangeQA = G1(ExchangeQAX, ExchangeQAY);
		G1Value encapsulateQB = G1(EncapsulateQBX, EncapsulateQBY);
		// H1 of Bob for the key exchange, which the example prints with the identifier 02 but computes with 03, as does its key; that of the encapsulation and encryption; that of Alice.
		BigInteger hB = Parse("9CB1F628 8CE0E510 43CE7234 4582FFC3 01E0A812 A7F5F200 4B85547A 24B82716");
		BigInteger hA = Parse("32DEE8AA D2DF2DB7 2C087F89 AA5FDA45 1B94D31A BD03F8E3 6A057FE2 CD160014");
		List<string> failures = [];
		CheckBaseG2(kernel, failures, SignMasterKey, SM9PairingTest.SignPublic);
		CheckBaseG2(kernel, failures, ExchangeT2, SM9PairingTest.ExchangeKeyA);
		CheckBaseG2(kernel, failures, ExchangeT4, SM9PairingTest.ExchangeKeyB);
		CheckBaseG2(kernel, failures, EncryptT2, SM9PairingTest.EncryptKey);
		CheckBaseG1(kernel, failures, SignT2, signKey);
		CheckBaseG1(kernel, failures, ExchangeMasterKey, exchangePublic);
		CheckBaseG1(kernel, failures, EncryptMasterKey, encryptPublic);
		CheckG1(kernel, failures, signKey, SignL, SM9PairingTest.Signature);
		CheckG1(kernel, failures, exchangeQB, ExchangeRA, SM9PairingTest.ExchangePointA);
		CheckG1(kernel, failures, exchangeQA, ExchangeRB, SM9PairingTest.ExchangePointB);
		CheckG1(kernel, failures, encapsulateQB, EncapsulateR, SM9PairingTest.EncapsulateC);
		CheckG1(kernel, failures, encapsulateQB, EncryptR, SM9PairingTest.EncryptC1);
		CheckUserKeyG1(kernel, failures, hB, exchangePublic, ExchangeRA, SM9PairingTest.ExchangePointA);
		CheckUserKeyG1(kernel, failures, hA, exchangePublic, ExchangeRB, SM9PairingTest.ExchangePointB);
		CheckUserKeyG1(kernel, failures, hB, encryptPublic, EncapsulateR, SM9PairingTest.EncapsulateC);
		CheckUserKeyG1(kernel, failures, hB, encryptPublic, EncryptR, SM9PairingTest.EncryptC1);
		CheckBaseAddG1(kernel, failures, hB, exchangePublic, exchangeQB);
		CheckBaseAddG1(kernel, failures, hA, exchangePublic, exchangeQA);
		CheckBaseAddG1(kernel, failures, hB, encryptPublic, encapsulateQB);
		FieldElement<SM9Order> h1 = Scalar(Parse(VerifyH1));
		SM9Point<SM9Fp2> signPublic = Projective(SM9PairingTest.SignPublic, Fp2Value.One);
		kernel.MultiplyBaseAddVariableTimeG2(in h1, in signPublic, out SM9Point<SM9Fp2> verifyP);

		if (ValueOf(verifyP) != SM9PairingTest.VerifyP)
		{
			failures.Add("P = [h1]P2 + Ppub-s");
		}

		await Assert.That(failures).IsEmpty();
	}

	private static (SM9AffinePoint<SM9Fp>, SM9AffinePoint<SM9Fp>, SM9AffinePoint<SM9Fp2>, SM9AffinePoint<SM9Fp2>)[] ComputeProductPairs()
	{
		Random random = new(5);
		return [.. Enumerable.Range(0, 3).Select(_ => (Element(Multiply(P1, RandomBelow(random, N - 1) + 1)!), Element(Multiply(P1, RandomBelow(random, N - 1) + 1)!), Element(Multiply(P2, RandomBelow(random, N - 1) + 1)!), Element(Multiply(P2, RandomBelow(random, N - 1) + 1)!)))];
	}

	private static (BigInteger, BigInteger, SM9AffinePoint<SM9Fp>, SM9AffinePoint<SM9Fp2>)[] ComputeBilinearCases()
	{
		Random random = new(1);
		return [.. Enumerable.Range(0, 3).Select(_ =>
		{
			BigInteger a = RandomBelow(random, N - 1) + 1;
			BigInteger b = RandomBelow(random, N - 1) + 1;
			return (a, b, Element(Multiply(P1, a)!), Element(Multiply(P2, b)!));
		})];
	}

	private static PowerCases ComputePowerCases()
	{
		Random random = new(2);
		G1Value point = Multiply(P1, RandomBelow(random, N - 1) + 1)!;
		Fp12Value pairing = Pairing(point, P2);
		return new PowerCases(Element(point), pairing, [.. ((List<BigInteger>)[0, .. Scalars(random, RandomCount)]).Select(k => (k, pairing.Pow(k)))]);
	}

	// The tables of a point as a key has them, public and secret, the second of another width; for the sums that may be the point at infinity, 5·P1 − 5·P1 and a·P1 + b·Q for Q = λP1 and a = −bλ, the point −5·P1 and the table of Q.
	private static G1Cases ComputeG1Cases()
	{
		Random random = new(3);
		G1Value point = Multiply(P1, RandomBelow(random, N - 1) + 1)!;
		G1Value addend = Multiply(P1, RandomBelow(random, N - 1) + 1)!;
		SM9AffinePoint<SM9Fp> ePoint = Element(point);
		SM9AffinePoint<SM9Fp> multiple = Element(Multiply(P1, Lambda)!);
		(BigInteger, G1Value?, G1Value?, G1Value?, G1Value?)[] products = [.. ((List<BigInteger>)[0, .. Scalars(random, RandomCount)]).Select(k =>
		{
			G1Value? expected = Multiply(point, k);
			G1Value? expectedBase = Multiply(P1, k);
			return (k, expectedBase, expected, Add(Multiply(P1, ModN(k * 3 + 1)), expected), Add(expectedBase, addend));
		})];
		return new G1Cases(ePoint, Projective(addend, 7), new SM9BaseTable<SM9Fp>(in ePoint, 5), new SM9BaseTable<SM9Fp>(in ePoint, 4, true), products, Projective(Negate(Multiply(P1, 5)), 3), new SM9BaseTable<SM9Fp>(in multiple, 5));
	}

	private static (SM9Point<SM9Fp2>, (BigInteger, G2Value?, G2Value?)[]) ComputeG2Products()
	{
		Random random = new(4);
		G2Value addend = Multiply(P2, RandomBelow(random, N - 1) + 1)!;
		return (Projective(addend, new Fp2Value(3, 5)), [.. ((List<BigInteger>)[0, .. Scalars(random, RandomCount)]).Select(k =>
		{
			G2Value? expected = Multiply(P2, k);
			return (k, expected, Add(expected, addend));
		})]);
	}

	private static (G2Value, SM9Point<SM9Fp2>, G2Value?)[] ComputeLoopProducts()
	{
		Random random = new(20);
		BigInteger a = 6 * T + 2;
		List<(G2Value, SM9Point<SM9Fp2>, G2Value?)> products = [];

		for (int i = 0; i < 8; ++i)
		{
			G2Value inside = Multiply(P2, RandomBelow(random, N - 1) + 1)!;
			G2Value? outside = null;

			while (outside is null)
			{
				outside = TwistPoint(RandomFp2(random));
			}

			foreach (G2Value point in (G2Value[])[inside, outside])
			{
				products.Add((point, Projective(point, i is 0 ? Fp2Value.One : RandomFp2(random)), Multiply(point, a)));
			}
		}

		return [.. products];
	}

	private static (G2Value[], SM9Point<SM9Fp2>[]) ComputeAffineCases()
	{
		Random random = new(10);
		G2Value[] values = [.. Enumerable.Range(0, SM9MillerLoop.LineCount).Select(_ => Multiply(P2, RandomBelow(random, N - 1) + 1)!)];
		return (values, [.. values.Select(v => Projective(v, new Fp2Value(RandomBelow(random, P), RandomBelow(random, P - 1) + 1)))]);
	}

	// B, 2B, … L·B for the base B of a window, each by adding B to the one before.
	private static T?[] WindowMultiples<T>(T? windowBase, int length, Func<T?, T?, T?> add) where T : class
	{
		T?[] multiples = new T?[length];
		T? sum = null;

		for (int j = 0; j < length; ++j)
		{
			sum = add(sum, windowBase);
			multiples[j] = sum;
		}

		return multiples;
	}

	private static SM9Fp12 Pair(SM9KernelCase kernel, in SM9AffinePoint<SM9Fp> p, in SM9AffinePoint<SM9Fp2> q)
	{
		kernel.MillerLoop(in p, in q, out SM9Fp12 f);
		kernel.FinalExponentiation(in f, out SM9Fp12 result);
		return result;
	}

	private static string ValueOfHex(in SM9Fp12 value)
	{
		return ValueOf(value).ToHex();
	}

	private static void CheckBaseG1(SM9KernelCase kernel, List<string> failures, string k, G1Value expected)
	{
		FieldElement<SM9Order> scalar = Scalar(Parse(k));
		kernel.MultiplyBaseG1(SM9G1Group.BaseTable, in scalar, out SM9Point<SM9Fp> product);

		if (ValueOf(product) != expected)
		{
			failures.Add($"[{k}]P1");
		}
	}

	private static void CheckBaseG2(SM9KernelCase kernel, List<string> failures, string k, G2Value expected)
	{
		FieldElement<SM9Order> scalar = Scalar(Parse(k));
		kernel.MultiplyBaseG2(in scalar, out SM9Point<SM9Fp2> baseProduct);

		if (ValueOf(baseProduct) != expected)
		{
			failures.Add($"[{k}]P2");
		}
	}

	private static void CheckG1(SM9KernelCase kernel, List<string> failures, G1Value point, string k, G1Value expected)
	{
		FieldElement<SM9Order> scalar = Scalar(Parse(k));
		SM9AffinePoint<SM9Fp> ePoint = Element(point);
		kernel.MultiplyG1(in ePoint, in scalar, out SM9Point<SM9Fp> product);
		kernel.MultiplyVariableTimeG1(in ePoint, in scalar, out SM9Point<SM9Fp> variableTimeProduct);

		if (ValueOf(product) != expected || ValueOf(variableTimeProduct) != expected)
		{
			failures.Add($"[{k}]P");
		}
	}

	// [r]Q = [r·h1]P1 + [r]Ppub-e for the user public key Q = [h1]P1 + Ppub-e, from the tables of P1 and Ppub-e, as an encryption or key exchange takes it once its key has the table.
	private static void CheckUserKeyG1(SM9KernelCase kernel, List<string> failures, BigInteger h1, G1Value masterPublicKey, string r, G1Value expected)
	{
		BigInteger k = Parse(r);
		FieldElement<SM9Order> baseScalar = Scalar(ModN(k * h1));
		FieldElement<SM9Order> scalar = Scalar(k);
		SM9AffinePoint<SM9Fp> point = Element(masterPublicKey);
		SM9BaseTable<SM9Fp> table = new(in point, 5);
		kernel.MultiplyBaseSumG1(SM9G1Group.BaseTable, in baseScalar, table, in scalar, out SM9Point<SM9Fp> product);

		if (ValueOf(product) != expected)
		{
			failures.Add($"[{r}]Q");
		}
	}

	private static void CheckBaseAddG1(SM9KernelCase kernel, List<string> failures, BigInteger k, G1Value addend, G1Value expected)
	{
		FieldElement<SM9Order> scalar = Scalar(k);
		SM9Point<SM9Fp> eAddend = Projective(addend, 1);
		kernel.MultiplyBaseAddVariableTimeG1(in scalar, in eAddend, out SM9Point<SM9Fp> sum);

		if (ValueOf(sum) != expected)
		{
			failures.Add($"[{k:X}]P1 + Q");
		}
	}
}
