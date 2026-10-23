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
			ProjectiveValue sum = curve.Add(reference.Randomize(left, random), reference.Randomize(right, random));
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

			ProjectiveValue sum = curve.Add(reference.Randomize(left, random), right);
			CheckPoint(failures, reference, $"{Show(left)} + affine {Show(right)}", sum, reference.Add(left, right));
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
			ProjectiveValue twice = curve.Double(reference.Randomize(point, random));
			CheckPoint(failures, reference, $"2 · {Show(point)}", twice, reference.Add(point, point));
		}

		await Assert.That(failures).IsEmpty();
	}

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
			ProjectiveValue left = reference.Randomize(point, random);
			ProjectiveValue right = reference.Randomize(i % 2 is 0 ? point : reference.RandomPoint(random), random);
			CurvePoint affine = reference.RandomPoint(random);

			foreach (ResultAliasing aliasing in (ResultAliasing[])[ResultAliasing.Left, ResultAliasing.Right])
			{
				CheckSame(failures, $"Add over {aliasing}", curve.Add(left, right, aliasing), curve.Add(left, right));
			}

			CheckSame(failures, "mixed Add in place", curve.Add(left, affine, true), curve.Add(left, affine));
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
			CurvePoint actual = curve.ToAffine(reference.Randomize(point, random));

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

	private static void CheckSame(List<string> failures, string operation, ProjectiveValue actual, ProjectiveValue expected)
	{
		if (actual != expected)
		{
			failures.Add($"{operation} gave {actual}, expected {expected}");
		}
	}
}
