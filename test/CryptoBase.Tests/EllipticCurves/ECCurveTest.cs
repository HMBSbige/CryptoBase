using CryptoBase.EllipticCurves;
using CryptoBase.KeyAgreements.Ecdh;
using CryptoBase.Signatures.Ecdsa;
using System.Diagnostics.CodeAnalysis;
using System.Reflection;

namespace CryptoBase.Tests.EllipticCurves;

public class ECCurveTest
{
	[Test]
	public async Task EveryCurveIsListed()
	{
		Type[] curves = [.. typeof(IECCurve).Assembly.GetTypes().Where(static type => type.GetInterfaces().Contains(typeof(IECCurve)))];

		await Assert.That(CurveCase.All().Select(static curve => curve.CurveType)).IsEquivalentTo(curves);
	}

	// The cases name their fields themselves, so this keeps them on the fields that CurveFields.cs picks.
	[Test]
	public async Task CasesUseTheFieldsOfTheLibrary()
	{
		Type[] fields = [FieldOf(typeof(EcdsaP256)), FieldOf(typeof(EcdsaP384)), FieldOf(typeof(EcdsaP521)), FieldOf(typeof(EcdhSM2))];

		await Assert.That(CurveCase.All().Select(static curve => curve.FieldType).Distinct()).IsEquivalentTo(fields);
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task TypesMatchTheCurve(CurveCase curve)
	{
		ECReference reference = curve.Reference;

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
		ECReference reference = curve.Reference;

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
		ECReference reference = curve.Reference;

		using (Assert.Multiple())
		{
			await Assert.That(reference.IsOnCurve(reference.Generator)).IsTrue();
			await Assert.That(reference.Multiply(reference.Generator, reference.N)).IsNull();
		}
	}

	private static Type FieldOf([DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.NonPublicFields)] Type type)
	{
		return type.GetField("_key", BindingFlags.NonPublic | BindingFlags.Instance)!.FieldType.GetGenericArguments()[1];
	}
}
