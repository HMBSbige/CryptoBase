using System.Numerics;

namespace CryptoBase.Tests.EllipticCurves;

public class FieldElementTest
{
	private const int RandomCount = 128;

	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task AddMatchesBigInteger(ModulusCase modulus)
	{
		BigInteger m = modulus.Modulus;
		List<string> failures = [];

		foreach ((BigInteger left, BigInteger right) in Pairs(modulus, 1))
		{
			Check(failures, $"{left:X} + {right:X}", modulus.Add(left, right), (left + right) % m);
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task MultiplyMatchesBigInteger(ModulusCase modulus)
	{
		BigInteger m = modulus.Modulus;
		BigInteger rInverse = RInverse(modulus);
		List<string> failures = [];

		foreach ((BigInteger left, BigInteger right) in Pairs(modulus, 5))
		{
			Check(failures, $"{left:X} · {right:X}", modulus.Multiply(left, right), left * right * rInverse % m);
		}

		await Assert.That(failures).IsEmpty();
	}

	// Before its final subtraction a product is a value u below 2m, which Reduce gives. Where 2m > R, random operands give u below m and u of R or more, which carries out of the top limb, about equally often. u in [m, R) is rare for them; the next test builds operands that give it.
	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task MultiplyTakesBothSidesOfTheFinalSubtraction(ModulusCase modulus)
	{
		BigInteger m = modulus.Modulus;
		BigInteger r = modulus.R;
		BigInteger rInverse = RInverse(modulus);
		int below = 0;
		int carried = 0;
		Random random = new(16);
		List<string> failures = [];

		for (int i = 0; i < 2 * RandomCount; ++i)
		{
			BigInteger left = modulus.RandomBelow(random, m);
			BigInteger right = modulus.RandomBelow(random, m);

			BigInteger u = modulus.Reduce(left * right);
			below += u < m ? 1 : 0;
			carried += u >= r ? 1 : 0;
			Check(failures, $"{left:X} · {right:X}", modulus.Multiply(left, right), left * right * rInverse % m);
		}

		await Assert.That(failures).IsEmpty();

		if (2 * m > r)
		{
			await Assert.That(below).IsPositive();
			await Assert.That(carried).IsPositive();
		}
	}

	// A Reduce of Montgomery rounds adds Q·m for a Q below R, so x·y + Q·m = u·R. For u in [m, R) and a y, x = u·R·y⁻¹ mod m makes x·y ≡ u·R mod m, and then Q = (u·R − x·y) / m, which is below R if x·y > (u − m)·R.
	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task MultiplySubtractsTheModulusFromAProductThatDoesNotCarry(ModulusCase modulus)
	{
		BigInteger m = modulus.Modulus;
		BigInteger r = modulus.R;
		BigInteger rInverse = RInverse(modulus);
		BigInteger[] targets = [m, m + 1, m + (BigInteger.One << 64), (m + r) / 2, r - 1];
		int reached = 0;
		Random random = new(17);
		List<string> failures = [];

		foreach (BigInteger u in targets.Where(u => u < r))
		{
			for (int i = 0; i < 8; ++i)
			{
				BigInteger y = i < 4 ? m - 1 - i : modulus.RandomBelow(random, m);
				BigInteger x = u * r % m * BigInteger.ModPow(y, m - 2, m) % m;

				if (x * y <= (u - m) * r)
				{
					continue;
				}

				reached += modulus.Reduce(x * y) == u ? 1 : 0;
				Check(failures, $"{x:X} · {y:X}", modulus.Multiply(x, y), x * y * rInverse % m);
				Check(failures, $"{y:X} · {x:X}", modulus.Multiply(y, x), x * y * rInverse % m);
				Check(failures, $"{x:X} · {y:X} over the left", modulus.Multiply(x, y, ResultAliasing.Left), x * y * rInverse % m);
			}
		}

		await Assert.That(failures).IsEmpty();
		await Assert.That(reached).IsPositive();
	}

	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task MontgomeryFormRoundTrips(ModulusCase modulus)
	{
		BigInteger m = modulus.Modulus;
		BigInteger r = modulus.R;
		List<string> failures = [];

		// Multiplying by the plain 1 leaves the Montgomery form.
		foreach (BigInteger value in Values(modulus, 7))
		{
			BigInteger montgomery = modulus.ToMontgomery(value);
			Check(failures, $"{value:X} · R", montgomery, value * r % m);
			Check(failures, $"{value:X} · R · R⁻¹", modulus.Multiply(montgomery, 1), value);
		}

		Check(failures, "1 · R", modulus.MontgomeryOne, r % m);
		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task InvertGivesTheInverseInMontgomeryForm(ModulusCase modulus)
	{
		await Assert.That(InversionFailures(modulus, modulus.Invert)).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task InvertVariableTimeGivesTheInverseInMontgomeryForm(ModulusCase modulus)
	{
		await Assert.That(InversionFailures(modulus, modulus.InvertVariableTime)).IsEmpty();
	}

	// Some boundary values differ from zero in a single limb.
	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task IsZeroComparesEveryLimb(ModulusCase modulus)
	{
		List<string> failures = [];

		foreach (BigInteger value in modulus.BoundaryValues())
		{
			if (modulus.IsZero(value) != Mask(value.IsZero))
			{
				failures.Add($"IsZero({value:X})");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task TryImportAcceptsExactlyTheValuesBelowTheModulus(ModulusCase modulus)
	{
		BigInteger m = modulus.Modulus;
		BigInteger limit = BigInteger.One << 8 * modulus.ByteLength;
		List<string> failures = [];

		foreach (BigInteger value in Values(modulus, 10))
		{
			if (!modulus.TryImport(modulus.Encode(value), out BigInteger imported) || imported != value)
			{
				failures.Add($"{value:X} was rejected or read as {imported:X}");
			}
		}

		SortedSet<BigInteger> rejected = [m, m + 1, BigInteger.One << modulus.BitLength, limit - 1];
		Random random = new(11);

		for (int k = 0; k < modulus.LimbCount; ++k)
		{
			rejected.Add(m + (BigInteger.One << 64 * k));
		}

		for (int i = 0; i < RandomCount; ++i)
		{
			rejected.Add(m + modulus.RandomBelow(random, limit - m));
		}

		foreach (BigInteger value in rejected.Where(value => value < limit))
		{
			if (modulus.TryImport(modulus.Encode(value), out BigInteger imported) || !imported.IsZero)
			{
				failures.Add($"{value:X} was accepted or read as {imported:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task ImportReducedReducesEveryValueOfTheEncodingLength(ModulusCase modulus)
	{
		BigInteger m = modulus.Modulus;
		BigInteger power = BigInteger.One << modulus.BitLength;
		BigInteger limit = BigInteger.One << 8 * modulus.ByteLength;
		SortedSet<BigInteger> values = [.. Values(modulus, 12), m, m + 1, 2 * m - 1, 2 * m, power - 1, power, power + 1, limit - 1];
		Random random = new(13);
		List<string> failures = [];

		for (int i = 0; i < RandomCount; ++i)
		{
			values.Add(modulus.RandomBelow(random, limit));
			values.Add(m + modulus.RandomBelow(random, limit - m));
		}

		values.RemoveWhere(value => value >= limit);

		foreach (BigInteger value in values)
		{
			Check(failures, $"{value:X} mod m", modulus.ImportReduced(modulus.Encode(value)), value % m);
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task ExportWritesTheBigEndianEncoding(ModulusCase modulus)
	{
		List<string> failures = [];

		foreach (BigInteger value in Values(modulus, 14))
		{
			if (!modulus.Export(value).AsSpan().SequenceEqual(modulus.Encode(value)))
			{
				failures.Add($"{value:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task ResultMayOverwriteAnInput(ModulusCase modulus)
	{
		List<string> failures = [];
		Random random = new(15);

		for (int i = 0; i < 16; ++i)
		{
			BigInteger left = modulus.PatternedValue(random);
			BigInteger right = modulus.RandomBelow(random, modulus.Modulus);

			foreach (ResultAliasing aliasing in (ResultAliasing[])[ResultAliasing.Left, ResultAliasing.Right])
			{
				string over = $"{left:X}, {right:X} over {aliasing}";
				Check(failures, $"Add {over}", modulus.Add(left, right, aliasing), modulus.Add(left, right));
				Check(failures, $"Multiply {over}", modulus.Multiply(left, right, aliasing), modulus.Multiply(left, right));
			}

			string inPlace = $"{left:X} in place";
			Check(failures, $"ToMontgomery {inPlace}", modulus.ToMontgomery(left, true), modulus.ToMontgomery(left));
			Check(failures, $"Invert {inPlace}", modulus.Invert(left, true), modulus.Invert(left));
			Check(failures, $"InvertVariableTime {inPlace}", modulus.InvertVariableTime(left, true), modulus.InvertVariableTime(left));
		}

		await Assert.That(failures).IsEmpty();
	}

	private static List<string> InversionFailures(ModulusCase modulus, Func<BigInteger, bool, BigInteger> invert)
	{
		BigInteger m = modulus.Modulus;
		BigInteger rSquared = modulus.R * modulus.R % m;
		BigInteger one = modulus.R % m;
		List<string> failures = [];

		foreach (BigInteger value in InversionValues(modulus))
		{
			// value = aR stands for a, so the inverse a⁻¹R is value⁻¹R²; the inverse of 0 is taken to be 0.
			BigInteger inverse = invert(value, false);
			BigInteger valueInverse = EcReference.Inverse(value, m);
			Check(failures, $"1 / {value:X}", inverse, valueInverse * rSquared % m);
			Check(failures, $"1 / {value:X} through the Montgomery form", modulus.Multiply(invert(modulus.ToMontgomery(value), false), 1), valueInverse);

			if (!value.IsZero)
			{
				Check(failures, $"{value:X} · 1 / {value:X}", modulus.Multiply(value, inverse), one);
			}
		}

		return failures;
	}

	// The divsteps of an inversion read the low bits of the value first and reach the high ones last, so runs of zeros or ones at either end, as in powers of two and in values with only their low or only their high bits set, steer them to extremes.
	private static SortedSet<BigInteger> InversionValues(ModulusCase modulus)
	{
		BigInteger m = modulus.Modulus;
		BigInteger top = BigInteger.One << modulus.BitLength;
		SortedSet<BigInteger> values = [.. Values(modulus, 8, 16)];

		for (int k = 0; k <= modulus.BitLength; ++k)
		{
			BigInteger power = BigInteger.One << k;
			values.UnionWith([power, power - 1, top - power, m - power]);
		}

		values.RemoveWhere(value => value < 0 || value >= m);
		return values;
	}

	private static void Check(List<string> failures, string operation, BigInteger actual, BigInteger expected)
	{
		if (actual != expected)
		{
			failures.Add($"{operation} gave {actual:X}, expected {expected:X}");
		}
	}

	private static ulong Mask(bool condition)
	{
		return condition ? ulong.MaxValue : 0;
	}

	private static BigInteger RInverse(ModulusCase modulus)
	{
		BigInteger m = modulus.Modulus;
		return BigInteger.ModPow(modulus.R, m - 2, m);
	}

	private static IEnumerable<(BigInteger Left, BigInteger Right)> Pairs(ModulusCase modulus, int seed)
	{
		BigInteger[] values = modulus.BoundaryValues();

		foreach (BigInteger left in values)
		{
			foreach (BigInteger right in values)
			{
				yield return (left, right);
			}
		}

		Random random = new(seed);

		for (int i = 0; i < RandomCount; ++i)
		{
			yield return (modulus.RandomBelow(random, modulus.Modulus), modulus.RandomBelow(random, modulus.Modulus));
			yield return (modulus.PatternedValue(random), modulus.PatternedValue(random));
		}
	}

	private static IEnumerable<BigInteger> Values(ModulusCase modulus, int seed, int randomCount = RandomCount)
	{
		foreach (BigInteger value in modulus.BoundaryValues())
		{
			yield return value;
		}

		Random random = new(seed);

		for (int i = 0; i < randomCount; ++i)
		{
			yield return modulus.RandomBelow(random, modulus.Modulus);
			yield return modulus.PatternedValue(random);
		}
	}
}
