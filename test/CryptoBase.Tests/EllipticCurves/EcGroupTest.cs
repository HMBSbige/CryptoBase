using static CryptoBase.Tests.EllipticCurves.EcTestUtils;

namespace CryptoBase.Tests.EllipticCurves;

public class EcGroupTest
{
	private const int RandomCount = 16;

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task AddMatchesTheReference(CurveCase curve)
	{
		EcReference reference = curve.Reference;
		Random random = new(1);
		List<string> failures = [];

		foreach ((CurvePoint? left, CurvePoint? right) in Pairs(reference, random))
		{
			JacobianValue sum = curve.Add(reference.RandomizeJacobian(left, random), reference.RandomizeJacobian(right, random));
			CheckPoint(failures, reference, $"{Show(left)} + {Show(right)}", sum, reference.Add(left, right));
		}

		await Assert.That(failures).IsEmpty();
	}

	// The affine right input cannot be the point at infinity.
	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task MixedAddMatchesTheReference(CurveCase curve)
	{
		EcReference reference = curve.Reference;
		Random random = new(2);
		List<string> failures = [];

		foreach ((CurvePoint? left, CurvePoint? right) in Pairs(reference, random))
		{
			if (right is null)
			{
				continue;
			}

			JacobianValue sum = curve.Add(reference.RandomizeJacobian(left, random), right);
			CheckPoint(failures, reference, $"{Show(left)} + affine {Show(right)}", sum, reference.Add(left, right));
		}

		await Assert.That(failures).IsEmpty();
	}

	// Equal points give (0, 0, 0) and set the mask; any other two points not at infinity give their sum, the point at infinity for opposite points.
	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task AddDistinctMatchesTheReference(CurveCase curve)
	{
		EcReference reference = curve.Reference;
		Random random = new(6);
		List<string> failures = [];

		foreach ((CurvePoint? left, CurvePoint? right) in Pairs(reference, random))
		{
			if (left is null || right is null)
			{
				continue;
			}

			bool equal = left == right;
			JacobianValue[] lefts = [reference.RandomizeJacobian(left, random), reference.RandomizeJacobian(left, random)];
			(string Name, (JacobianValue Sum, ulong Equal) Result)[] results =
			[
				("", curve.AddDistinct(lefts[0], reference.RandomizeJacobian(right, random))),
				("affine ", curve.AddDistinct(lefts[1], right)),
			];

			foreach ((string name, (JacobianValue sum, ulong mask)) in results)
			{
				string operation = $"{Show(left)} + {name}{Show(right)}";

				if (mask != (equal ? ulong.MaxValue : 0))
				{
					failures.Add($"{operation} gave the mask {mask:X}");
				}

				if (equal)
				{
					if (sum != new JacobianValue(0, 0, 0))
					{
						failures.Add($"{operation} gave {sum}, expected (0, 0, 0)");
					}
				}
				else
				{
					CheckPoint(failures, reference, operation, sum, reference.Add(left, right));
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task DoubleMatchesTheReference(CurveCase curve)
	{
		EcReference reference = curve.Reference;
		Random random = new(3);
		List<string> failures = [];

		foreach (CurvePoint? point in Points(reference, random))
		{
			JacobianValue twice = curve.Double(reference.RandomizeJacobian(point, random));
			CheckPoint(failures, reference, $"2 · {Show(point)}", twice, reference.Add(point, point));
		}

		await Assert.That(failures).IsEmpty();
	}

	// Each mask of the complete additions reads the inputs after the formula, so the pairs include equal and opposite points and the point at infinity on either side.
	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task ResultMayOverwriteAnInput(CurveCase curve)
	{
		EcReference reference = curve.Reference;
		Random random = new(4);
		List<string> failures = [];

		for (int i = 0; i < RandomCount; ++i)
		{
			CurvePoint point = reference.RandomPoint(random);
			(CurvePoint? first, CurvePoint? second) = (i % 5) switch
			{
				0 => (point, point),
				1 => (point, reference.Negate(point)),
				2 => (point, null),
				3 => (null, point),
				_ => (point, reference.RandomPoint(random))
			};

			JacobianValue left = reference.RandomizeJacobian(first, random);
			JacobianValue right = reference.RandomizeJacobian(second, random);
			CurvePoint affine = second ?? point;

			foreach (ResultAliasing aliasing in (ResultAliasing[])[ResultAliasing.Left, ResultAliasing.Right])
			{
				CheckSame(failures, $"Add over {aliasing}", curve.Add(left, right, aliasing), curve.Add(left, right));
				CheckSame(failures, $"AddDistinct over {aliasing}", curve.AddDistinct(left, right, aliasing), curve.AddDistinct(left, right));
			}

			CheckSame(failures, "mixed Add in place", curve.Add(left, affine, true), curve.Add(left, affine));
			CheckSame(failures, "mixed AddDistinct in place", curve.AddDistinct(left, affine, true), curve.AddDistinct(left, affine));
			CheckSame(failures, "Double in place", curve.Double(left, true), curve.Double(left));
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task ToAffineDividesByZ(CurveCase curve)
	{
		EcReference reference = curve.Reference;
		Random random = new(5);
		List<string> failures = [];

		foreach (CurvePoint? point in Points(reference, random))
		{
			CurvePoint actual = curve.ToAffine(reference.RandomizeJacobian(point, random));

			if (actual != (point ?? new CurvePoint(0, 0)))
			{
				failures.Add($"{Show(point)} became {Show(actual)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	internal static IEnumerable<CurvePoint?> Points(EcReference reference, Random random)
	{
		yield return null;
		yield return reference.Generator;

		for (int i = 0; i < RandomCount; ++i)
		{
			CurvePoint point = reference.RandomPoint(random);
			yield return point;
			yield return reference.Negate(point);
		}
	}

	internal static IEnumerable<(CurvePoint? Left, CurvePoint? Right)> Pairs(EcReference reference, Random random)
	{
		yield return (null, null);

		foreach (CurvePoint? point in Points(reference, random))
		{
			yield return (point, point);
			yield return (point, reference.Negate(point));
			yield return (point, null);
			yield return (null, point);
			yield return (point, reference.RandomPoint(random));
			yield return (point, reference.Add(point, point));
		}
	}
}
