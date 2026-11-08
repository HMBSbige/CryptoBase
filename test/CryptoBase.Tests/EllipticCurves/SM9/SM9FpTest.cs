using CryptoBase.EllipticCurves.SM9;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9Reference;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9TestUtils;

namespace CryptoBase.Tests.EllipticCurves.SM9;

public class SM9FpTest
{
	private const int RandomCount = 40;

	private static readonly BigInteger RInverse = Inverse(MontgomeryR);

	private static readonly BigInteger Two260 = BigInteger.One << 260;

	[Test]
	public async Task ProductsMatchBigInteger()
	{
		List<string> failures = [];
		Random random = new(1);
		List<SM9Fp> values = ReducedElements(random, RandomCount);
		// Inputs that the tower passes: sums of two reduced elements, and 3p − y, below 5.25p, for a reduced y.
		List<SM9Fp> sums = [];
		List<SM9Fp> differences = [];

		foreach (SM9Fp y in values.Take(12))
		{
			SM9Fp.AddUnreduced(in y, in y, out SM9Fp sum);
			sums.Add(sum);
			SM9Fp zero = default;
			SM9Fp.SubtractUnreduced(in zero, in y, out SM9Fp difference);
			differences.Add(difference);
		}

		foreach (SM9Fp x in values)
		{
			foreach (SM9Fp y in (List<SM9Fp>)[.. values.Take(16), .. differences])
			{
				SM9Fp.Multiply(in x, in y, out SM9Fp product);
				Check(failures, $"Multiply {Show(x)}, {Show(y)}", product, RawValue(x) * RawValue(y) * RInverse);
			}

			SM9Fp.Square(in x, out SM9Fp square);
			Check(failures, $"Square {Show(x)}", square, RawValue(x) * RawValue(x) * RInverse);
		}

		foreach (SM9Fp x in sums)
		{
			foreach (SM9Fp y in sums)
			{
				SM9Fp.Multiply(in x, in y, out SM9Fp product);
				Check(failures, $"Multiply {Show(x)}, {Show(y)}", product, RawValue(x) * RawValue(y) * RInverse);
			}

			SM9Fp.Square(in x, out SM9Fp square);
			Check(failures, $"Square {Show(x)}", square, RawValue(x) * RawValue(x) * RInverse);
		}

		foreach (SM9Fp x in differences)
		{
			SM9Fp.Square(in x, out SM9Fp square);
			Check(failures, $"Square {Show(x)}", square, RawValue(x) * RawValue(x) * RInverse);
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task ResultsMayAliasInputs()
	{
		Random random = new(2);
		SM9Fp x = Raw(RandomBelow(random, P));
		SM9Fp y = Raw(RandomBelow(random, P));
		BigInteger vx = RawValue(x);
		BigInteger vy = RawValue(y);
		SM9Fp a = x;
		SM9Fp.Multiply(in a, in y, out a);
		SM9Fp b = y;
		SM9Fp.Multiply(in x, in b, out b);
		SM9Fp c = x;
		SM9Fp.Multiply(in c, in c, out c);
		SM9Fp d = x;
		SM9Fp.Square(in d, out d);
		SM9Fp e = x;
		SM9Fp.Add(in e, in e, out e);
		SM9Fp f = x;
		SM9Fp.Subtract(in f, in y, out f);
		SM9Fp g = y;
		SM9Fp.Subtract(in x, in g, out g);
		SM9Fp h = x;
		SM9Fp.Invert(in h, out h);

		using (Assert.Multiple())
		{
			await Assert.That(Mod(RawValue(a))).IsEqualTo(Mod(vx * vy * RInverse));
			await Assert.That(Mod(RawValue(b))).IsEqualTo(Mod(vx * vy * RInverse));
			await Assert.That(Mod(RawValue(c))).IsEqualTo(Mod(vx * vx * RInverse));
			await Assert.That(Mod(RawValue(d))).IsEqualTo(Mod(vx * vx * RInverse));
			await Assert.That(Mod(RawValue(e))).IsEqualTo(Mod(2 * vx));
			await Assert.That(Mod(RawValue(f))).IsEqualTo(Mod(vx - vy));
			await Assert.That(Mod(RawValue(g))).IsEqualTo(Mod(vx - vy));
			await Assert.That(Mod(RawValue(h) * vx)).IsEqualTo(Mod(MontgomeryR * MontgomeryR));
		}
	}

	// Sums of products up to the 28p² that Reduce takes, with columns of either sign: a0b0 − 2a1b1 + 11p², the shape of Fp2, and sums of products of sums.
	[Test]
	public async Task WideSumsReduce()
	{
		List<string> failures = [];
		Random random = new(3);
		List<SM9Fp> values = ReducedElements(random, 12);

		foreach (SM9Fp x in values)
		{
			foreach (SM9Fp y in values)
			{
				SM9Fp.MultiplyWide(in x, in y, out SM9FpWide xy);
				SM9Fp.MultiplyWide(in y, in y, out SM9FpWide yy);
				SM9FpWide.SubtractTwice(in xy, in yy, out SM9FpWide combined);
				SM9Fp.Reduce(in combined, out SM9Fp reduced);
				Check(failures, $"Reduce xy − 2y² {Show(x)}, {Show(y)}", reduced, (RawValue(x) * RawValue(y) - 2 * RawValue(y) * RawValue(y) + 11 * P * P) * RInverse);
				SM9Fp.AddUnreduced(in x, in y, out SM9Fp sum);
				SM9Fp.MultiplyWide(in sum, in sum, out SM9FpWide square);
				SM9FpWide.Subtract(in square, in xy, out SM9FpWide difference);
				SM9Fp.Reduce(in difference, out reduced);
				Check(failures, $"Reduce (x + y)² − xy {Show(x)}, {Show(y)}", reduced, (RawValue(sum) * RawValue(sum) - RawValue(x) * RawValue(y)) * RInverse);
				SM9Fp.SquareWide(in sum, out SM9FpWide squareWide);
				SM9FpWide.Add(in squareWide, in xy, out SM9FpWide total);
				SM9Fp.Reduce(in total, out reduced);
				Check(failures, $"Reduce (x + y)² + xy {Show(x)}, {Show(y)}", reduced, (RawValue(sum) * RawValue(sum) + RawValue(x) * RawValue(y)) * RInverse);
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task SumsAndDifferencesMatchBigInteger()
	{
		List<string> failures = [];
		Random random = new(4);
		List<SM9Fp> values = ReducedElements(random, RandomCount);
		SM9Fp zero = default;

		foreach (SM9Fp x in values)
		{
			foreach (SM9Fp y in values.Take(16))
			{
				SM9Fp.Add(in x, in y, out SM9Fp sum);
				Check(failures, $"Add {Show(x)}, {Show(y)}", sum, RawValue(x) + RawValue(y));
				SM9Fp.Subtract(in x, in y, out SM9Fp difference);
				Check(failures, $"Subtract {Show(x)}, {Show(y)}", difference, RawValue(x) - RawValue(y));
				SM9Fp.SubtractUnreduced(in x, in y, out SM9Fp unreduced);

				if (RawValue(unreduced) != RawValue(x) + 3 * P - RawValue(y) || LimbsOf(unreduced).Any(static limb => limb >= 1UL << 55))
				{
					failures.Add($"SubtractUnreduced {Show(x)}, {Show(y)}");
				}
			}

			SM9Fp.Negate(in x, out SM9Fp negated);
			Check(failures, $"Negate {Show(x)}", negated, -RawValue(x));
			SM9Fp.MultiplyByThreeB(in x, out SM9Fp tripled);
			Check(failures, $"MultiplyByThreeB {Show(x)}", tripled, 15 * RawValue(x));

			foreach (uint k in (uint[])[0, 1, 2, 3, 5, 9])
			{
				SM9Fp.MultiplySmall(in x, k, out SM9Fp scaled);
				Check(failures, $"MultiplySmall {Show(x)}, {k}", scaled, k * RawValue(x));
			}

			SM9Fp.Subtract(in zero, in x, out SM9Fp fromZero);
			Check(failures, $"Subtract 0, {Show(x)}", fromZero, -RawValue(x));
		}

		await Assert.That(failures).IsEmpty();
	}

	// WeakReduce takes limbs below 2^62 and values below 2^260, the extremes included, where the quotient is at its largest.
	[Test]
	public async Task WeakReductionKeepsTheValue()
	{
		List<string> failures = [];
		Random random = new(5);
		List<BigInteger> values = [0, P, 2 * P, 3 * P - 1, 22 * P, Two260 - 1, Two260 - P, (BigInteger.One << 256) * 15];

		for (int i = 0; i < RandomCount; ++i)
		{
			values.Add(RandomBelow(random, Two260));
		}

		foreach (BigInteger value in values)
		{
			SM9Fp raw = Raw(value);
			SM9Fp.WeakReduce(in raw, out SM9Fp reduced);
			Check(failures, $"WeakReduce {Show(raw)}", reduced, value);
		}

		// Limbs that hold more than 52 bits each, as sums of limbs do.
		for (int i = 0; i < RandomCount; ++i)
		{
			ulong l0 = (ulong)random.NextInt64() >> 2;
			ulong l1 = (ulong)random.NextInt64() >> 2;
			ulong l2 = (ulong)random.NextInt64() >> 2;
			ulong l3 = (ulong)random.NextInt64() >> 2;
			SM9Fp limbs = Limbs(l0, l1, l2, l3, 0);
			BigInteger low = RawValue(limbs);
			ulong l4 = (ulong)(Two260 - 1 - low >> 208);
			limbs.L4 = l4;
			SM9Fp.WeakReduce(in limbs, out SM9Fp reduced);
			Check(failures, $"WeakReduce {Show(limbs)}", reduced, RawValue(limbs));
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task ZeroTestsAndEqualityHoldModP()
	{
		Random random = new(6);
		List<string> failures = [];

		foreach (SM9Fp x in ReducedElements(random, RandomCount))
		{
			bool zero = Mod(RawValue(x)).IsZero;

			if (SM9Fp.IsZero(in x) != (zero ? ulong.MaxValue : 0))
			{
				failures.Add($"IsZero {Show(x)}");
			}

			SM9Fp same = Raw(Mod(RawValue(x)));

			if (SM9Fp.AreEqual(in x, in same) != ulong.MaxValue)
			{
				failures.Add($"AreEqual {Show(x)}");
			}

			SM9Fp other = Raw(Mod(RawValue(x) + 1));

			if (SM9Fp.AreEqual(in x, in other) != 0)
			{
				failures.Add($"AreEqual {Show(x)} + 1");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task InversesMatchBigInteger()
	{
		List<string> failures = [];
		Random random = new(7);

		foreach (SM9Fp x in ReducedElements(random, 12))
		{
			BigInteger plain = Mod(RawValue(x) * RInverse);
			BigInteger expected = plain.IsZero ? 0 : Mod(Inverse(plain) * MontgomeryR);
			SM9Fp.Invert(in x, out SM9Fp inverse);
			SM9Fp.InvertVariableTime(in x, out SM9Fp inverseVariableTime);

			if (RawValue(inverse) != expected || RawValue(inverseVariableTime) != expected)
			{
				failures.Add($"Invert {Show(x)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task EncodingsRoundTripAndRejectValuesFromP()
	{
		Random random = new(8);
		List<string> failures = [];
		byte[] bytes = new byte[SM9Fp.ByteLength];

		foreach (SM9Fp x in ReducedElements(random, RandomCount))
		{
			BigInteger canonical = Mod(RawValue(x));

			if (!SM9Fp.TryImport(Encode(canonical), out SM9Fp imported) || RawValue(imported) != canonical)
			{
				failures.Add($"TryImport {Show(x)}");
			}

			SM9Fp.ToMontgomery(in imported, out SM9Fp montgomery);
			SM9Fp.ExportPlain(in montgomery, bytes);

			if (Mod(RawValue(montgomery)) != Mod(canonical * MontgomeryR) || !bytes.AsSpan().SequenceEqual(Encode(canonical)) || !IsReduced(montgomery))
			{
				failures.Add($"Montgomery form {Show(x)}");
			}

			// Out of Montgomery form from every reduced value, the edges included.
			SM9Fp.ExportPlain(in x, bytes);

			if (!bytes.AsSpan().SequenceEqual(Encode(ValueOf(x))))
			{
				failures.Add($"ExportPlain {Show(x)}");
			}
		}

		foreach (BigInteger value in (BigInteger[])[P, P + 1, (BigInteger.One << 256) - 1])
		{
			if (SM9Fp.TryImport(Encode(value), out SM9Fp rejected) || RawValue(rejected) != 0)
			{
				failures.Add($"TryImport {value:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	private static void Check(List<string> failures, string operation, in SM9Fp actual, BigInteger expected)
	{
		if (!IsReduced(actual) || Mod(RawValue(actual)) != Mod(expected))
		{
			failures.Add($"{operation} gave {Show(actual)}, expected {Mod(expected):X}");
		}
	}
}
