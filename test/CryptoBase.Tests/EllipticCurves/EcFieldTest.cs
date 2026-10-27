using CryptoBase.EllipticCurves;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using static CryptoBase.Tests.EllipticCurves.EcTestUtils;

namespace CryptoBase.Tests.EllipticCurves;

// The tests that every field of unsaturated limbs shares, against BigInteger. Limbs hold limbBits bits each when canonical; the form that the members take has every limb but the top one below formLow, which is 2^limbBits or twice that, and the top one below formTop. A value v also stands as v + kp for every k that fits, with limbs 2^limbBits or more where formLow allows. R is the Montgomery factor, 1 for a field that does not use it, and canonical elements have the top limb below canonicalTop. The two long chains take the seeds chainSeed and chainSeed + 1.
internal abstract class EcFieldTest<TCurve, TField, TOrder>(int limbBits, ulong formLow, ulong formTop, BigInteger r, ulong canonicalTop, int chainSeed)
	where TCurve : struct, IEcCurve
	where TField : unmanaged, IEcField<TField>
	where TOrder : unmanaged, IMontgomeryModulus
{
	private protected const int RandomCount = 32;

	// ReSharper disable once StaticMemberInGenericType
	private protected static readonly BigInteger P = ModulusCase.FromLimbs(TField.Modulus);

	private protected static readonly int LimbCount = Unsafe.SizeOf<TField>() / sizeof(ulong);

	private static readonly CurveCase Curve = CurveCase.All().Single(curve => curve.FieldType == typeof(TField));

	private protected readonly ulong Low = 1UL << limbBits;

	private protected readonly BigInteger R = r;

	private protected readonly BigInteger RInverse = BigInteger.ModPow(r, P - 2, P);

	// The largest value of the form: every limb at its most.
	private protected readonly BigInteger Largest = ValueOf(limbBits, [.. Enumerable.Repeat(formLow - 1, LimbCount - 1), formTop - 1]);

	// Limbs 0 to n − 2 at 2^limbBits or more where they can be, if the form allows them there.
	private protected readonly bool[] AllHigh = [.. Enumerable.Repeat(formLow > 1UL << limbBits, LimbCount - 1)];

	private protected readonly bool[] AllLow = new bool[LimbCount - 1];

	private readonly int _limbBits = limbBits;

	private readonly ulong _formLow = formLow;

	private readonly ulong _formTop = formTop;

	[Test]
	public async Task ArithmeticMatchesBigInteger()
	{
		List<string> failures = [];
		Random random = new(1);

		foreach ((TField x, TField y) in Pairs(random))
		{
			BigInteger a = ValueOf(x);
			BigInteger b = ValueOf(y);
			string operands = $"{ShowLimbs(x)}, {ShowLimbs(y)}";
			TField.Multiply(in x, in y, out TField product);
			CheckProduct(failures, $"Multiply {operands}", product, a, b);
			TField.Square(in x, out product);
			CheckProduct(failures, $"Square {ShowLimbs(x)}", product, a, a);
			TField.Add(in x, in y, out TField sum);
			CheckReduced(failures, $"Add {operands}", sum, a + b);
			TField.Subtract(in x, in y, out TField difference);
			CheckReduced(failures, $"Subtract {operands}", difference, a - b);
			TField.Negate(in y, out TField negated);
			CheckReduced(failures, $"Negate {ShowLimbs(y)}", negated, -b);
			TField.ToMontgomery(in x, out TField montgomery);
			CheckProduct(failures, $"ToMontgomery {ShowLimbs(x)}", montgomery, a, R * R % P);
			TField.FromMontgomery(in x, out TField plain);
			CheckProduct(failures, $"FromMontgomery {ShowLimbs(x)}", plain, a, 1);
		}

		await Assert.That(failures).IsEmpty();
	}

	// Every multiple of p in the form is 0, and its neighbours are not.
	[Test]
	public async Task ZeroTestsReduceFirst()
	{
		List<string> failures = [];
		Random random = new(4);
		List<BigInteger> values = [0, 1, P - 1, P + 1, 2 * P - 1, 2 * P + 1, Largest];

		for (int i = 0; i < RandomCount; ++i)
		{
			values.Add(RandomBelow(random, P));
		}

		values.AddRange([Largest - 1, Low, Low - 1]);

		foreach (BigInteger value in values)
		{
			foreach (TField x in Representations(value, random))
			{
				ulong expected = Mod(value).IsZero ? ulong.MaxValue : 0;

				if (TField.IsZero(in x) != expected)
				{
					failures.Add($"IsZero {ShowLimbs(x)}");
				}

				foreach (TField y in Representations(value, random))
				{
					if (TField.AreEqual(in x, in y) != ulong.MaxValue)
					{
						failures.Add($"AreEqual {ShowLimbs(x)}, {ShowLimbs(y)}");
					}
				}

				foreach (TField y in Representations(value + 1, random))
				{
					if (TField.AreEqual(in x, in y) is not 0)
					{
						failures.Add($"AreEqual {ShowLimbs(x)}, {ShowLimbs(y)}");
					}
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task ExportAndInversionReduceFirst()
	{
		List<string> failures = [];
		Random random = new(5);

		foreach (BigInteger value in Residues(random))
		{
			foreach (TField x in Representations(value, random))
			{
				byte[] exported = new byte[TField.ByteLength];
				TField.Export(in x, exported);

				if (!exported.AsSpan().SequenceEqual(Curve.EncodeCoordinate(value)))
				{
					failures.Add($"Export {ShowLimbs(x)}");
				}

				// value = aR stands for a, so the inverse a⁻¹R is value⁻¹R²; value^(p − 2) also maps 0 to 0.
				BigInteger inverse = BigInteger.ModPow(value, P - 2, P) * R % P * R % P;
				TField.Invert(in x, out TField result);
				CheckCanonical(failures, $"Invert {ShowLimbs(x)}", result, inverse);
				TField.InvertVariableTime(in x, out result);
				CheckCanonical(failures, $"InvertVariableTime {ShowLimbs(x)}", result, inverse);
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task ImportsGiveCanonicalLimbs()
	{
		List<string> failures = [];
		Random random = new(6);

		foreach (BigInteger value in Residues(random))
		{
			ulong[] limbs = [.. Enumerable.Range(0, (TField.ByteLength + 7) / 8).Select(i => (ulong)(value >> 64 * i & ulong.MaxValue))];
			TField.FromLimbs(limbs, out TField element);
			CheckCanonical(failures, $"FromLimbs {value:X}", element, value);

			if (!TField.TryImport(Curve.EncodeCoordinate(value), out element))
			{
				failures.Add($"TryImport {value:X} failed");
			}

			CheckCanonical(failures, $"TryImport {value:X}", element, value);
		}

		foreach (BigInteger value in (BigInteger[])[P, P + 1, (BigInteger.One << 8 * TField.ByteLength) - 1])
		{
			if (TField.TryImport(Curve.EncodeCoordinate(value), out TField element) || ValueOf(element) != 0)
			{
				failures.Add($"TryImport {value:X} accepted or left {ShowLimbs(element)}");
			}
		}

		CheckCanonical(failures, "One", TField.One, R % P);
		await Assert.That(failures).IsEmpty();
	}

	// The formulas leave out reductions between steps, so their inputs take every coordinate at the limits of the form, including a Z of 0 written as a multiple of p.
	[Test]
	public async Task FormulasMatchTheReferenceForCoordinatesAtTheLimits()
	{
		EcReference reference = Curve.Reference;
		Random random = new(7);
		List<string> failures = [];

		foreach ((CurvePoint? left, CurvePoint? right) in EcGroupTest.Pairs(reference, random))
		{
			string operation = $"{Show(left)} + {Show(right)}";
			JacobianPoint<TField> x = Loose(reference.RandomizeJacobian(left, random), random);
			JacobianPoint<TField> y = Loose(reference.RandomizeJacobian(right, random), random);
			EcGroup<TCurve, TField, TOrder>.Double(in x, out JacobianPoint<TField> twice);
			CheckPoint(failures, reference, $"2 · {Show(left)}", twice, reference.Add(left, left));
			EcGroup<TCurve, TField, TOrder>.Add(in x, in y, out JacobianPoint<TField> sum);
			CheckPoint(failures, reference, operation, sum, reference.Add(left, right));

			if (right is null)
			{
				continue;
			}

			AffinePoint<TField> affine = Loose(right, random);
			EcGroup<TCurve, TField, TOrder>.Add(in x, in affine, out sum);
			CheckPoint(failures, reference, $"{operation}, affine", sum, reference.Add(left, right));

			if (left is null)
			{
				continue;
			}

			ulong mask = EcGroup<TCurve, TField, TOrder>.AddDistinct(in x, in y, out sum);
			CheckDistinct(failures, reference, operation, mask, sum, left, right);
			mask = EcGroup<TCurve, TField, TOrder>.AddDistinct(in x, in affine, out sum);
			CheckDistinct(failures, reference, $"{operation}, affine", mask, sum, left, right);
		}

		await Assert.That(failures).IsEmpty();
	}

	// Results feed the next step unreduced, for thousands of steps: doublings and complete additions of G and of 2kG to kG, checked against the reference along the way.
	[Test]
	public async Task LongChainsOfFormulasStayInForm()
	{
		EcReference reference = Curve.Reference;
		BigInteger n = Curve.Order;
		Random random = new(chainSeed);
		AffinePoint<TField> generator = Loose(reference.Generator, random);
		JacobianPoint<TField> point = Loose(reference.RandomizeJacobian(reference.Generator, random), random);
		BigInteger k = 1;
		List<string> failures = [];

		for (int i = 1; i <= 4000 && failures.Count is 0; ++i)
		{
			switch (random.Next(4))
			{
				case 0:
					EcGroup<TCurve, TField, TOrder>.Add(in point, in generator, out point);
					k += 1;
					break;
				case 1:
					EcGroup<TCurve, TField, TOrder>.Double(in point, out JacobianPoint<TField> twice);
					EcGroup<TCurve, TField, TOrder>.Add(in point, in twice, out point);
					k *= 3;
					break;
				default:
					EcGroup<TCurve, TField, TOrder>.Double(in point, out point);
					k *= 2;
					break;
			}

			k %= n;

			if (!IsInForm(point.X) || !IsInForm(point.Y) || !IsInForm(point.Z))
			{
				failures.Add($"step {i} left the form");
			}

			if (i % 250 is 0)
			{
				CheckPoint(failures, reference, $"step {i}", point, reference.Multiply(reference.Generator, k));
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The field members chain as well: each result is the next input, and the inputs keep to the form.
	[Test]
	public async Task LongChainsOfArithmeticStayInForm()
	{
		Random random = new(chainSeed + 1);
		TField x = Represent(Largest, AllHigh)!.Value;
		TField y = Loose(RandomBelow(random, P), random);
		BigInteger a = Mod(ValueOf(x));
		BigInteger b = Mod(ValueOf(y));
		List<string> failures = [];

		for (int i = 0; i < 20000 && failures.Count is 0; ++i)
		{
			switch (random.Next(6))
			{
				case 0:
					TField.Multiply(in x, in y, out x);
					a = a * b * RInverse % P;
					break;
				case 1:
					TField.Square(in x, out x);
					a = a * a * RInverse % P;
					break;
				case 2:
					TField.Add(in x, in y, out x);
					a = (a + b) % P;
					break;
				case 3:
					TField.Subtract(in y, in x, out x);
					a = Mod(b - a);
					break;
				case 4:
					TField.Negate(in x, out x);
					a = Mod(-a);
					break;
				default:
					(x, y, a, b) = (y, x, b, a);
					break;
			}

			if (Mod(ValueOf(x)) != a || !IsInForm(x))
			{
				failures.Add($"step {i} gave {ShowLimbs(x)}, expected {a:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Checks a result of Multiply, Square, ToMontgomery or FromMontgomery of operands of the values x and y.
	private protected abstract void CheckProduct(List<string> failures, string operation, in TField actual, BigInteger x, BigInteger y);

	// Checks a result of Add, Subtract or Negate.
	private protected abstract void CheckReduced(List<string> failures, string operation, in TField actual, BigInteger expected);

	// Below p, with residues that sit next to the limb boundaries.
	private protected virtual IEnumerable<BigInteger> Residues(Random random)
	{
		SortedSet<BigInteger> values = [0, 1, 2, P - 1, P - 2, R % P, R * R % P, (BigInteger.One << 8 * TField.ByteLength) - P, Mod(Largest)];
		AddLimbBoundaries(values);

		for (int i = 0; i < RandomCount; ++i)
		{
			values.Add(RandomBelow(random, P));
		}

		values.RemoveWhere(value => value < 0 || value >= P);
		return values;
	}

	private protected void AddLimbBoundaries(SortedSet<BigInteger> values)
	{
		for (int k = 1; k < LimbCount; ++k)
		{
			BigInteger power = BigInteger.One << _limbBits * k;
			values.UnionWith([power - 1, power, power + 1, P - power, P - power + 1]);
		}
	}

	private IEnumerable<(TField Left, TField Right)> Pairs(Random random)
	{
		BigInteger[] residues = [.. Residues(random)];

		foreach (BigInteger left in residues)
		{
			foreach (BigInteger right in residues)
			{
				yield return (Canonical(left), Canonical(right));
				yield return (Loose(left, random), Loose(right, random));
				yield return (Highest(left), Highest(right));
			}
		}

		TField largest = Represent(Largest, AllHigh)!.Value;
		yield return (largest, largest);
	}

	// The representations of value + kp in the form, for every k, with limbs 0 to n − 2 below 2^limbBits and, where the form allows more, at 2^limbBits or more where they can be, or either at random.
	private protected IEnumerable<TField> Representations(BigInteger value, Random random)
	{
		value = Mod(value);

		for (BigInteger u = value; u <= Largest; u += P)
		{
			bool[][] highs = _formLow > Low ? [AllLow, AllHigh, [.. Enumerable.Range(0, LimbCount - 1).Select(_ => random.Next(2) is 0)]] : [AllLow];

			foreach (bool[] high in highs)
			{
				if (Represent(u, high) is { } element)
				{
					yield return element;
				}
			}
		}
	}

	private TField Canonical(BigInteger value)
	{
		return Represent(Mod(value), AllLow)!.Value;
	}

	// The representation with the largest value, with limbs 0 to n − 2 at 2^limbBits or more where they can be.
	private TField Highest(BigInteger value)
	{
		BigInteger u = Mod(value);
		u += (Largest - u) / P * P;
		return Represent(u, AllHigh) ?? Represent(u, AllLow)!.Value;
	}

	private protected TField Loose(BigInteger value, Random random)
	{
		TField[] representations = [.. Representations(value, random)];
		return representations[random.Next(representations.Length)];
	}

	// Montgomery coordinates, loose.
	private JacobianPoint<TField> Loose(JacobianValue value, Random random)
	{
		return new JacobianPoint<TField> { X = Loose(value.X * R, random), Y = Loose(value.Y * R, random), Z = Loose(value.Z * R, random) };
	}

	private AffinePoint<TField> Loose(CurvePoint point, Random random)
	{
		return new AffinePoint<TField> { X = Loose(point.X * R, random), Y = Loose(point.Y * R, random) };
	}

	// Limbs of u, each of 0 to n − 2 taking an extra 2^limbBits from the limb above where high says so and u allows; null if the top limb does not fit the form.
	private protected TField? Represent(BigInteger u, bool[] high)
	{
		ulong[] limbs = new ulong[LimbCount];

		for (int i = 0; i < LimbCount - 1; ++i)
		{
			BigInteger limb = u & Low - 1;

			if (high[i] && u >= limb + Low)
			{
				limb += Low;
			}

			limbs[i] = (ulong)limb;
			u = u - limb >> _limbBits;
		}

		if (u >= _formTop)
		{
			return null;
		}

		limbs[^1] = (ulong)u;
		return Limbs(limbs);
	}

	private protected static TField Limbs(params ReadOnlySpan<ulong> limbs)
	{
		return MemoryMarshal.Read<TField>(MemoryMarshal.AsBytes(limbs));
	}

	private protected BigInteger ValueOf(in TField value)
	{
		return ValueOf(_limbBits, LimbsOf(value));
	}

	private static BigInteger ValueOf(int limbBits, ReadOnlySpan<ulong> limbs)
	{
		BigInteger result = 0;

		for (int i = limbs.Length - 1; i >= 0; --i)
		{
			result = (result << limbBits) + limbs[i];
		}

		return result;
	}

	// The plain coordinates of the Montgomery ones.
	private protected JacobianValue Value(in JacobianPoint<TField> point)
	{
		return new JacobianValue(Mod(ValueOf(point.X) * RInverse), Mod(ValueOf(point.Y) * RInverse), Mod(ValueOf(point.Z) * RInverse));
	}

	private protected bool IsInForm(in TField value)
	{
		return IsInForm(value, _formLow, _formTop);
	}

	private protected static bool IsInForm(in TField value, ulong low, ulong top)
	{
		ReadOnlySpan<ulong> limbs = LimbsOf(value);
		return !limbs.Slice(0, LimbCount - 1).ContainsAnyInRange(low, ulong.MaxValue) && limbs[^1] < top;
	}

	private void CheckCanonical(List<string> failures, string operation, in TField actual, BigInteger expected)
	{
		if (ValueOf(actual) != expected || !IsInForm(actual, Low, canonicalTop))
		{
			failures.Add($"{operation} gave {ShowLimbs(actual)}, expected {expected:X}");
		}
	}

	private protected void CheckPoint(List<string> failures, EcReference reference, string operation, in JacobianPoint<TField> actual, CurvePoint? expected)
	{
		if (!IsInForm(actual.X) || !IsInForm(actual.Y) || !IsInForm(actual.Z))
		{
			failures.Add($"{operation} gave ({ShowLimbs(actual.X)}, {ShowLimbs(actual.Y)}, {ShowLimbs(actual.Z)}), out of the form");
		}

		EcTestUtils.CheckPoint(failures, reference, operation, Value(actual), expected);
	}

	// Equal points give (0, 0, 0) and set the mask; any others give their sum.
	private void CheckDistinct(List<string> failures, EcReference reference, string operation, ulong mask, in JacobianPoint<TField> actual, CurvePoint left, CurvePoint right)
	{
		bool equal = left == right;

		if (mask != (equal ? ulong.MaxValue : 0))
		{
			failures.Add($"AddDistinct {operation} gave the mask {mask:X}");
		}

		if (!equal)
		{
			CheckPoint(failures, reference, $"AddDistinct {operation}", actual, reference.Add(left, right));
		}
		else if (Value(actual) != new JacobianValue(0, 0, 0))
		{
			failures.Add($"AddDistinct {operation} gave {Value(actual)}, expected (0, 0, 0)");
		}
	}

	private protected static BigInteger Mod(BigInteger value)
	{
		BigInteger remainder = value % P;
		return remainder.Sign < 0 ? remainder + P : remainder;
	}

	private protected static ulong Next(Random random, ulong bound)
	{
		return (ulong)random.NextInt64(long.MinValue, long.MaxValue) % bound;
	}

	private protected static BigInteger RandomBelow(Random random, BigInteger bound)
	{
		return EcReference.RandomBelow(random, bound);
	}

	private protected static string ShowLimbs(in TField value)
	{
		return $"[{string.Join(", ", LimbsOf(value).ToArray().Select(static limb => $"{limb:X}"))}]";
	}

	private static ReadOnlySpan<ulong> LimbsOf(in TField value)
	{
		return MemoryMarshal.Cast<TField, ulong>(new ReadOnlySpan<TField>(in value));
	}
}
