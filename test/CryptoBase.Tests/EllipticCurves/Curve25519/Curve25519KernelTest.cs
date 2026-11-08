using CryptoBase.EllipticCurves.Curve25519;
using System.Collections.Concurrent;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.Curve25519.Curve25519Reference;
using static CryptoBase.Tests.EllipticCurves.Curve25519.Curve25519TestUtils;
using static CryptoBase.Tests.EllipticCurves.Curve25519.Field25519TestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.EllipticCurves.Curve25519;

// Checks every kernel against Curve25519Reference, with points of every order and u-coordinates of the curve, of its twist and of p or more, and with the largest limbs that a tight input may have.
public class Curve25519KernelTest
{
	private const int RandomCount = 10;

	private static readonly BigInteger A = 486662;

	private static readonly ConcurrentDictionary<(EdwardsValue Value, BigInteger A, BigInteger B), Lazy<EdwardsValue>> DoubleProducts = new();

	[Test]
	public async Task EveryKernelIsListed()
	{
		await Assert.That(Curve25519KernelCase.All().Select(static kernel => kernel.KernelType)).IsEquivalentTo(ImplementationsOf(typeof(ICurve25519Kernel)));
	}

	[Test]
	[MethodDataSource(typeof(Curve25519KernelCase), nameof(Curve25519KernelCase.All))]
	public async Task LadderMatchesTheReference(Curve25519KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(1);
		List<BigInteger> us = [0, 1, 9, P - 1, P, P + 1, (BigInteger.One << 255) - 1, .. TorsionPoints().Select(ToMontgomeryU)];
		int twist = 0;

		for (int i = 0; i < RandomCount; ++i)
		{
			BigInteger u = RandomBelow(random, BigInteger.One << 255);
			us.Add(u);
			twist += IsSquare(u * u * u + A * u * u + u) ? 0 : 1;
		}

		List<string> failures = [];
		List<Field25519> elements = [.. us.Select(static u => FromBytes(u)), LargestTight];

		foreach (Field25519 element in elements)
		{
			BigInteger u = ValueOf(element);

			foreach (byte[] scalar in ClampedScalars(random))
			{
				kernel.Ladder(scalar, in element, out Field25519 x, out Field25519 z);
				BigInteger expected = Ladder(DecodeInteger(scalar), u);
				BigInteger actual = Mod(ValueOf(x) * Inverse(ValueOf(z)));

				if (actual != expected || !IsTight(x) || !IsTight(z))
				{
					failures.Add($"Ladder {Convert.ToHexString(scalar)}, {u:X} gave {actual:X}, expected {expected:X}");
				}
			}
		}

		using (Assert.Multiple())
		{
			await Assert.That(failures).IsEmpty();
			await Assert.That(twist).IsPositive();
		}
	}

	[Test]
	[MethodDataSource(typeof(Curve25519KernelCase), nameof(Curve25519KernelCase.All))]
	public async Task MultiplyBaseMatchesTheReference(Curve25519KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];

		foreach (BigInteger scalar in Scalars(new Random(2), RandomCount))
		{
			kernel.MultiplyBase(Scalar(scalar), out EdwardsPoint product);
			EdwardsValue expected = Multiply(Base, scalar);

			if (ToValue(product) != expected)
			{
				failures.Add($"MultiplyBase {scalar:X} gave {Show(ToValue(product))}, expected {Show(expected)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(Curve25519KernelCase), nameof(Curve25519KernelCase.All))]
	public async Task DoubleScalarMultiplyMatchesTheReference(Curve25519KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(3);
		List<BigInteger> scalars = Scalars(random, 2);
		EdwardsValue[] torsion = TorsionPoints();
		EdwardsValue[] points = [Identity, Base, torsion[1], torsion[2], torsion[4], Add(RandomPoint(random), torsion[5]), RandomPoint(random), RandomPoint(random)];
		List<string> failures = [];

		foreach ((EdwardsValue value, EdwardsPoint point) in Representations(points, random))
		{

			for (int i = 0; i < scalars.Count; ++i)
			{
				BigInteger a = scalars[i];
				BigInteger b = scalars[(i * 5 + 1) % scalars.Count];
				kernel.DoubleScalarMultiplyVariableTime(Scalar(a), in point, Scalar(b), out EdwardsPoint result);
				EdwardsValue expected = DoubleProduct(value, a, b);

				if (ToValue(result) != expected)
				{
					failures.Add($"DoubleScalarMultiplyVariableTime {a:X}, {Show(value)}, {b:X} gave {Show(ToValue(result))}, expected {Show(expected)}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(Curve25519KernelCase), nameof(Curve25519KernelCase.All))]
	public async Task DoubleScalarMultiplyWithTableMatchesTheReference(Curve25519KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(6);
		List<BigInteger> scalars = Scalars(random, 2);
		EdwardsValue[] torsion = TorsionPoints();
		EdwardsValue[] points = [Identity, Base, torsion[1], torsion[4], Add(RandomPoint(random), torsion[3]), RandomPoint(random)];
		List<string> failures = [];

		foreach ((EdwardsValue value, EdwardsPoint point) in Representations(points, random))
		{
			EdwardsNielsPoint[] table = EdwardsVariableTimePointTable.Build(in point);

			for (int i = 0; i < scalars.Count; ++i)
			{
				BigInteger a = scalars[i];
				BigInteger b = scalars[(i * 7 + 3) % scalars.Count];
				kernel.DoubleScalarMultiplyVariableTime(Scalar(a), table, Scalar(b), out EdwardsPoint result);
				EdwardsValue expected = DoubleProduct(value, a, b);

				if (ToValue(result) != expected)
				{
					failures.Add($"DoubleScalarMultiplyVariableTime {a:X}, table of {Show(value)}, {b:X} gave {Show(ToValue(result))}, expected {Show(expected)}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The fixed-base product mapped to Curve25519 is the ladder from u = 9, the image of B, as X25519 public keys need.
	[Test]
	[MethodDataSource(typeof(Curve25519KernelCase), nameof(Curve25519KernelCase.All))]
	public async Task MultiplyBaseAgreesWithTheLadderFromNine(Curve25519KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];
		Field25519 nine = Element(9);

		foreach (byte[] scalar in ClampedScalars(new Random(4)))
		{
			kernel.MultiplyBase(scalar, out EdwardsPoint product);
			byte[] fromEdwards = new byte[32];
			Edwards25519.ToMontgomeryU(in product, fromEdwards);
			kernel.Ladder(scalar, in nine, out Field25519 x, out Field25519 z);
			BigInteger fromLadder = Mod(ValueOf(x) * Inverse(ValueOf(z)));

			if (DecodeInteger(fromEdwards) != fromLadder)
			{
				failures.Add($"scalar {Convert.ToHexString(scalar)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	private static Field25519 FromBytes(BigInteger u)
	{
		Field25519.FromBytes(EncodeInteger(u), out Field25519 element);
		return element;
	}

	// Each point with a random Z, then with the largest tight limbs in Z.
	private static EdwardsValue DoubleProduct(EdwardsValue value, BigInteger a, BigInteger b)
	{
		return DoubleProducts.GetOrAdd((value, a, b), static key => new Lazy<EdwardsValue>(() => Add(Multiply(key.Value, key.A), Multiply(Base, key.B)))).Value;
	}

	private static IEnumerable<(EdwardsValue Value, EdwardsPoint Point)> Representations(EdwardsValue[] points, Random random)
	{
		foreach (EdwardsValue value in points)
		{
			yield return (value, ToPoint(value, 1 + RandomBelow(random, P - 1)));
			EdwardsPoint largest = ToPoint(value, ValueOf(LargestTight));
			largest.Z = LargestTight;
			yield return (value, largest);
		}
	}

	// Clamped scalars with the fewest and the most bits, and random ones.
	private static List<byte[]> ClampedScalars(Random random)
	{
		BigInteger lowest = BigInteger.One << 254;
		BigInteger highest = (BigInteger.One << 255) - 8;
		List<byte[]> scalars = [Scalar(lowest), Scalar(lowest + 8), Scalar(highest), Scalar(highest - 8 * L % (BigInteger.One << 254))];

		for (int i = 0; i < 4; ++i)
		{
			byte[] scalar = new byte[32];
			random.NextBytes(scalar);
			scalar[0] &= 0xF8;
			scalar[31] = (byte)(scalar[31] & 0x7F | 0x40);
			scalars.Add(scalar);
		}

		return scalars;
	}
}
