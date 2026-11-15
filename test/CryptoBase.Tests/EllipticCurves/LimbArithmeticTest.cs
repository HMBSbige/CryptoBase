using CryptoBase.EllipticCurves;

namespace CryptoBase.Tests.EllipticCurves;

// Multiply takes its portable path without BMI2 or Arm64 on .NET 10, as with DISABLE=AVX2, and from .NET 11 on only without X86Base either, as with DISABLE=HWIntrinsic.
// The boundary limbs give every carry between the 32-bit halves of the products.
public class LimbArithmeticTest
{
	private const int RandomCount = 4096;

	private static readonly ulong[] BoundaryLimbs =
	[
		0, 1, 2, 0xFFFFFFFF, 0x100000000, 0x100000001, 0x1FFFFFFFF, 0x7FFFFFFFFFFFFFFF,
		0x8000000000000000, 0xFFFFFFFF00000000, 0xFFFFFFFF00000001, 0xFFFFFFFFFFFFFFFE, ulong.MaxValue,
	];

	[Test]
	public async Task MultiplyMatchesUInt128()
	{
		List<string> failures = [];

		foreach ((ulong x, ulong y) in Pairs())
		{
			ulong high = LimbArithmetic.Multiply(x, y, out ulong low);

			if (new UInt128(high, low) != (UInt128)x * y)
			{
				failures.Add($"{x:X16} · {y:X16}: {high:X16}{low:X16}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task MultiplyAddMatchesUInt128()
	{
		List<string> failures = [];

		foreach ((ulong x, ulong y) in Pairs())
		{
			foreach ((ulong a, ulong b) in ((ulong, ulong)[])[(0, 0), (ulong.MaxValue, 0), (0, ulong.MaxValue), (ulong.MaxValue, ulong.MaxValue), (x, y)])
			{
				ulong high = LimbArithmetic.MultiplyAdd(x, y, a, b, out ulong low);

				if (new UInt128(high, low) != (UInt128)x * y + a + b)
				{
					failures.Add($"{x:X16} · {y:X16} + {a:X16} + {b:X16}: {high:X16}{low:X16}");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	private static IEnumerable<(ulong X, ulong Y)> Pairs()
	{
		foreach (ulong x in BoundaryLimbs)
		{
			foreach (ulong y in BoundaryLimbs)
			{
				yield return (x, y);
			}
		}

		Random random = new(1);

		for (int i = 0; i < RandomCount; ++i)
		{
			yield return ((ulong)random.NextInt64(long.MinValue, long.MaxValue), (ulong)random.NextInt64(long.MinValue, long.MaxValue));
		}
	}
}
