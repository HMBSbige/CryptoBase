using System.Numerics;

namespace CryptoBase.Tests.EllipticCurves;

public class FieldElementTest
{
	private const int RandomCount = 128;

	private static readonly uint[] SmallFactors = [0, 1, 2, 3, 4, 5, 7, 8, 12, 255, 256, 65537, uint.MaxValue];

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
	public async Task SubtractMatchesBigInteger(ModulusCase modulus)
	{
		BigInteger m = modulus.Modulus;
		List<string> failures = [];

		foreach ((BigInteger left, BigInteger right) in Pairs(modulus, 2))
		{
			Check(failures, $"{left:X} - {right:X}", modulus.Subtract(left, right), (left - right + m) % m);
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task NegateMatchesBigInteger(ModulusCase modulus)
	{
		BigInteger m = modulus.Modulus;
		List<string> failures = [];

		foreach (BigInteger value in Values(modulus, 3))
		{
			Check(failures, $"-{value:X}", modulus.Negate(value), (m - value) % m);
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task MultiplySmallMatchesBigInteger(ModulusCase modulus)
	{
		BigInteger m = modulus.Modulus;
		List<string> failures = [];

		foreach (BigInteger value in Values(modulus, 4))
		{
			foreach (uint factor in SmallFactors)
			{
				Check(failures, $"{factor} · {value:X}", modulus.MultiplySmall(value, factor), factor * value % m);
			}
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

	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task SquareMatchesBigInteger(ModulusCase modulus)
	{
		BigInteger m = modulus.Modulus;
		BigInteger rInverse = RInverse(modulus);
		List<string> failures = [];

		foreach (BigInteger value in Values(modulus, 6))
		{
			Check(failures, $"{value:X}²", modulus.Square(value), value * value * rInverse % m);
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task MontgomeryFormRoundTrips(ModulusCase modulus)
	{
		BigInteger m = modulus.Modulus;
		BigInteger r = modulus.R;
		BigInteger rInverse = RInverse(modulus);
		List<string> failures = [];

		foreach (BigInteger value in Values(modulus, 7))
		{
			BigInteger montgomery = modulus.ToMontgomery(value);
			Check(failures, $"{value:X} · R", montgomery, value * r % m);
			Check(failures, $"{value:X} · R⁻¹", modulus.FromMontgomery(value), value * rInverse % m);
			Check(failures, $"{value:X} · R · R⁻¹", modulus.FromMontgomery(montgomery), value);
		}

		Check(failures, "1 · R", modulus.MontgomeryOne, r % m);
		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task InvertGivesTheInverseInMontgomeryForm(ModulusCase modulus)
	{
		BigInteger m = modulus.Modulus;
		BigInteger rSquared = modulus.R * modulus.R % m;
		BigInteger one = modulus.R % m;
		List<string> failures = [];

		foreach (BigInteger value in Values(modulus, 8, 16))
		{
			// value = aR stands for a, so the inverse a⁻¹R is value⁻¹R²; value^(m − 2) also maps 0 to 0.
			BigInteger inverse = modulus.Invert(value);
			Check(failures, $"1 / {value:X}", inverse, BigInteger.ModPow(value, m - 2, m) * rSquared % m);
			Check(failures, $"1 / {value:X} through the Montgomery form", modulus.FromMontgomery(modulus.Invert(modulus.ToMontgomery(value))), BigInteger.ModPow(value, m - 2, m));

			if (!value.IsZero)
			{
				Check(failures, $"{value:X} · 1 / {value:X}", modulus.Multiply(value, inverse), one);
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task ConditionalSelectAndSwapFollowTheMask(ModulusCase modulus)
	{
		List<string> failures = [];

		foreach ((BigInteger left, BigInteger right) in Pairs(modulus, 9))
		{
			Check(failures, $"select {left:X} over {right:X}", modulus.ConditionalSelect(ulong.MaxValue, left, right), left);
			Check(failures, $"select {right:X} over {left:X}", modulus.ConditionalSelect(0, left, right), right);

			(BigInteger swappedLeft, BigInteger swappedRight) = modulus.ConditionalSwap(ulong.MaxValue, left, right);
			Check(failures, $"swap {left:X} with {right:X}, left", swappedLeft, right);
			Check(failures, $"swap {left:X} with {right:X}, right", swappedRight, left);

			(BigInteger keptLeft, BigInteger keptRight) = modulus.ConditionalSwap(0, left, right);
			Check(failures, $"keep {left:X} and {right:X}, left", keptLeft, left);
			Check(failures, $"keep {left:X} and {right:X}, right", keptRight, right);
		}

		await Assert.That(failures).IsEmpty();
	}

	// Some boundary values differ from zero, and from one another, in a single limb.
	[Test]
	[MethodDataSource(typeof(ModulusCase), nameof(ModulusCase.All))]
	public async Task IsZeroAndAreEqualCompareEveryLimb(ModulusCase modulus)
	{
		BigInteger[] values = modulus.BoundaryValues();
		List<string> failures = [];

		foreach (BigInteger left in values)
		{
			if (modulus.IsZero(left) != Mask(left.IsZero))
			{
				failures.Add($"IsZero({left:X})");
			}

			foreach (BigInteger right in values)
			{
				if (modulus.AreEqual(left, right) != Mask(left == right))
				{
					failures.Add($"AreEqual({left:X}, {right:X})");
				}
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
				Check(failures, $"Subtract {over}", modulus.Subtract(left, right, aliasing), modulus.Subtract(left, right));
				Check(failures, $"Multiply {over}", modulus.Multiply(left, right, aliasing), modulus.Multiply(left, right));
				Check(failures, $"ConditionalSelect set {over}", modulus.ConditionalSelect(ulong.MaxValue, left, right, aliasing), left);
				Check(failures, $"ConditionalSelect clear {over}", modulus.ConditionalSelect(0, left, right, aliasing), right);
			}

			string inPlace = $"{left:X} in place";
			Check(failures, $"Negate {inPlace}", modulus.Negate(left, true), modulus.Negate(left));
			Check(failures, $"MultiplySmall {inPlace}", modulus.MultiplySmall(left, 3, true), modulus.MultiplySmall(left, 3));
			Check(failures, $"Square {inPlace}", modulus.Square(left, true), modulus.Square(left));
			Check(failures, $"ToMontgomery {inPlace}", modulus.ToMontgomery(left, true), modulus.ToMontgomery(left));
			Check(failures, $"FromMontgomery {inPlace}", modulus.FromMontgomery(left, true), modulus.FromMontgomery(left));
			Check(failures, $"Invert {inPlace}", modulus.Invert(left, true), modulus.Invert(left));
		}

		await Assert.That(failures).IsEmpty();
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
