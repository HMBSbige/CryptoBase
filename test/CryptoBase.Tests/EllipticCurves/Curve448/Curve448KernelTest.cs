using CryptoBase.EllipticCurves.Curve448;
using System.Collections.Concurrent;
using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.Curve448.Curve448Reference;
using static CryptoBase.Tests.EllipticCurves.Curve448.Curve448TestUtils;
using static CryptoBase.Tests.EllipticCurves.Curve448.Field448TestUtils;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.EllipticCurves.Curve448;

public class Curve448KernelTest
{
	private const int RandomCount = 6;

	private static readonly BigInteger A = 156326;

	private static readonly ConcurrentDictionary<(EdwardsValue Value, BigInteger A, BigInteger B), Lazy<EdwardsValue>> DoubleProducts = new();

	[Test]
	public async Task EveryKernelIsListed()
	{
		await Assert.That(Curve448KernelCase.All().Select(static kernel => kernel.KernelType)).IsEquivalentTo(ImplementationsOf(typeof(ICurve448Kernel)));
	}

	[Test]
	[MethodDataSource(typeof(Curve448KernelCase), nameof(Curve448KernelCase.All))]
	public async Task LadderMatchesTheReference(Curve448KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(1);
		List<BigInteger> us = [0, 1, 5, P - 1, P, P + 1, (BigInteger.One << 448) - 1];
		int twist = 0;

		for (int i = 0; i < RandomCount; ++i)
		{
			BigInteger u = RandomBelow(random, BigInteger.One << 448);
			us.Add(u);
			twist += IsSquare(u * u * u + A * u * u + u) ? 0 : 1;
		}

		List<string> failures = [];
		List<Field448> elements = [.. us.Select(static u => FromBytes(u)), LargestTight];

		foreach (Field448 element in elements)
		{
			BigInteger u = ValueOf(element);

			foreach (byte[] scalar in ClampedScalars(random))
			{
				kernel.Ladder(scalar, in element, out Field448 x, out Field448 z);
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

	// RFC 7748 §5.2 and §6.2.
	[Test]
	[MethodDataSource(typeof(Curve448KernelCase), nameof(Curve448KernelCase.All))]
	public async Task LadderMatchesTheVectors(Curve448KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		using (Assert.Multiple())
		{
			await Assert.That(X448(kernel, "3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3", "06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086")).IsEqualTo("ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f");
			await Assert.That(X448(kernel, "203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f", "0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db")).IsEqualTo("884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d");
			await Assert.That(X448(kernel, "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b", FiveHex)).IsEqualTo("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0");
			await Assert.That(X448(kernel, "1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d", FiveHex)).IsEqualTo("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");
			await Assert.That(X448(kernel, "9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b", "3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609")).IsEqualTo("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");
		}
	}

	// RFC 7748 §5.2.
	[Test]
	[MethodDataSource(typeof(Curve448KernelCase), nameof(Curve448KernelCase.All))]
	public async Task IterationsMatchTheVectors(Curve448KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		string k = FiveHex;
		string u = FiveHex;
		string? afterOne = null;

		for (int i = 0; i < 1000; ++i)
		{
			(k, u) = (X448(kernel, k, u), k);
			afterOne ??= k;
		}

		using (Assert.Multiple())
		{
			await Assert.That(afterOne).IsEqualTo("3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113");
			await Assert.That(k).IsEqualTo("aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38");
		}
	}

	[Test]
	[MethodDataSource(typeof(Curve448KernelCase), nameof(Curve448KernelCase.All))]
	public async Task MultiplyBaseMatchesTheReference(Curve448KernelCase kernel)
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
	[MethodDataSource(typeof(Curve448KernelCase), nameof(Curve448KernelCase.All))]
	public async Task DoubleScalarMultiplyMatchesTheReference(Curve448KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(3);
		List<BigInteger> scalars = Scalars(random, 1);
		EdwardsValue[] torsion = TorsionPoints();
		EdwardsValue[] points = [Identity, Base, torsion[1], torsion[2], Add(RandomPoint(random), torsion[3]), RandomPoint(random)];
		List<string> failures = [];

		foreach ((EdwardsValue value, EdwardsPoint point) in Representations(points, random))
		{
			foreach ((BigInteger a, BigInteger b) in Pairs(scalars, 5, 1))
			{
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
	[MethodDataSource(typeof(Curve448KernelCase), nameof(Curve448KernelCase.All))]
	public async Task DoubleScalarMultiplyWithTableMatchesTheReference(Curve448KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		Random random = new(6);
		List<BigInteger> scalars = Scalars(random, 1);
		EdwardsValue[] torsion = TorsionPoints();
		EdwardsValue[] points = [Identity, Base, torsion[3], Add(RandomPoint(random), torsion[1]), RandomPoint(random)];
		List<string> failures = [];

		foreach ((EdwardsValue value, EdwardsPoint point) in Representations(points, random))
		{
			EdwardsAffinePoint[] table = EdwardsVariableTimePointTable.Build(in point);

			foreach ((BigInteger a, BigInteger b) in Pairs(scalars, 7, 3))
			{
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

	// The clamped scalar, a multiple of 4, goes into the ladder unchanged.
	[Test]
	[MethodDataSource(typeof(Curve448KernelCase), nameof(Curve448KernelCase.All))]
	public async Task MultiplyBaseAgreesWithTheLadderFromFive(Curve448KernelCase kernel)
	{
		SkipUnlessSupported(kernel);

		List<string> failures = [];
		Field448 five = Element(5);

		foreach (byte[] scalar in ClampedScalars(new Random(4)))
		{
			kernel.MultiplyBase(scalar, out EdwardsPoint product);
			byte[] fromEdwards = new byte[56];
			Edwards448.ToMontgomeryU(in product, fromEdwards);
			kernel.Ladder(scalar, in five, out Field448 x, out Field448 z);
			BigInteger fromLadder = Mod(ValueOf(x) * Inverse(ValueOf(z)));

			if (DecodeInteger(fromEdwards) != fromLadder || fromLadder != Ladder(DecodeInteger(scalar), 5))
			{
				failures.Add($"scalar {Convert.ToHexString(scalar)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// [a]value + [b]B, computed once for all kernels and representations.
	private static EdwardsValue DoubleProduct(EdwardsValue value, BigInteger a, BigInteger b)
	{
		return DoubleProducts.GetOrAdd((value, a, b), static key => new Lazy<EdwardsValue>(() => Add(Multiply(key.Value, key.A), Multiply(Base, key.B)))).Value;
	}

	private static IEnumerable<(BigInteger A, BigInteger B)> Pairs(List<BigInteger> scalars, int factor, int offset)
	{
		for (int i = 0; i < scalars.Count; ++i)
		{
			yield return (scalars[i], scalars[(i * factor + offset) % scalars.Count]);
		}

		yield return (0, 0);
	}

	private static string FiveHex => "05" + new string('0', 110);

	private static Field448 FromBytes(BigInteger u)
	{
		Field448.FromBytes(EncodeInteger(u), out Field448 element);
		return element;
	}

	private static string X448(Curve448KernelCase kernel, string scalar, string u)
	{
		byte[] clamped = Clamp(Convert.FromHexString(scalar));
		Field448 element = FromBytes(DecodeInteger(Convert.FromHexString(u)));
		kernel.Ladder(clamped, in element, out Field448 x, out Field448 z);
		return Convert.ToHexStringLower(EncodeInteger(Mod(ValueOf(x) * Inverse(ValueOf(z)))));
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

	private static List<byte[]> ClampedScalars(Random random)
	{
		BigInteger lowest = BigInteger.One << 447;
		BigInteger highest = (BigInteger.One << 448) - 4;
		List<byte[]> scalars = [Scalar(lowest), Scalar(lowest + 4), Scalar(highest), Scalar(4 * L)];

		for (int i = 0; i < 3; ++i)
		{
			byte[] scalar = new byte[56];
			random.NextBytes(scalar);
			scalar[0] &= 0xFC;
			scalar[55] |= 0x80;
			scalars.Add(scalar);
		}

		return scalars;
	}
}
