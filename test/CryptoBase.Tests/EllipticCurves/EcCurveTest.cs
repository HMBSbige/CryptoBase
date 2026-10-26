using CryptoBase.EllipticCurves;
using CryptoBase.Signatures.Ecdsa;
using System.Reflection;

namespace CryptoBase.Tests.EllipticCurves;

public class EcCurveTest
{
	[Test]
	public async Task EveryCurveIsListed()
	{
		Type[] curves = [.. typeof(IEcCurve).Assembly.GetTypes().Where(static type => type.GetInterfaces().Contains(typeof(IEcCurve)))];

		await Assert.That(CurveCase.All().Select(static curve => curve.CurveType)).IsEquivalentTo(curves);
	}

	// The cases name their fields themselves, so this keeps them on the fields that CurveFields.cs picks.
	[Test]
	public async Task CasesUseTheFieldsOfTheLibrary()
	{
		Type[] fields = [.. new[] { typeof(EcdsaP256), typeof(EcdsaP384), typeof(EcdsaP521) }.Select(static type => type.GetField("_key", BindingFlags.NonPublic | BindingFlags.Instance)!.FieldType.GetGenericArguments()[1])];

		await Assert.That(CurveCase.All().Select(static curve => curve.FieldType)).IsEquivalentTo(fields);
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task TypesMatchTheCurve(CurveCase curve)
	{
		EcReference reference = curve.Reference;

		using (Assert.Multiple())
		{
			await Assert.That(curve.FieldModulus).IsEqualTo(reference.P);
			await Assert.That(curve.OrderModulus).IsEqualTo(reference.N);
			await Assert.That(reference.A).IsEqualTo(reference.P - 3);
			await Assert.That(curve.Parameters.H).IsEqualTo(1);
			// ReduceX reads an x of FieldLength bytes as a scalar of ScalarLength bytes.
			await Assert.That(curve.FieldLength).IsEqualTo(curve.ScalarLength);
		}
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task ConstantsAreTheCurveParameters(CurveCase curve)
	{
		EcReference reference = curve.Reference;

		using (Assert.Multiple())
		{
			await Assert.That(curve.StoredB).IsEqualTo(reference.B);
			await Assert.That(curve.StoredGeneratorX).IsEqualTo(reference.Generator.X);
			await Assert.That(curve.StoredGeneratorY).IsEqualTo(reference.Generator.Y);
		}
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task GeneratorIsOnTheCurveWithOrderN(CurveCase curve)
	{
		EcReference reference = curve.Reference;

		using (Assert.Multiple())
		{
			await Assert.That(reference.IsOnCurve(reference.Generator)).IsTrue();
			await Assert.That(reference.Multiply(reference.Generator, reference.N)).IsNull();
		}
	}
}
