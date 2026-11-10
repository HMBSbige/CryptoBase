using CryptoBase.EllipticCurves;
using System.Numerics;

namespace CryptoBase.Tests.EllipticCurves;

internal static class ECTestUtils
{
	internal static void CheckPoint(List<string> failures, ECReference reference, string operation, JacobianValue actual, CurvePoint? expected)
	{
		if (!reference.IsOnJacobianCurve(actual))
		{
			failures.Add($"{operation} gave {actual}, which is not on the curve");
		}
		else if (!reference.Represents(actual, expected))
		{
			failures.Add($"{operation} gave {Show(reference.ToAffine(actual))}, expected {Show(expected)}");
		}
	}

	internal static void CheckSame<T>(List<string> failures, string operation, T actual, T expected)
	{
		if (!EqualityComparer<T>.Default.Equals(actual, expected))
		{
			failures.Add($"{operation} gave {actual}, expected {expected}");
		}
	}

	internal static string Show(CurvePoint? point)
	{
		return point is null ? "O" : $"({point.X:X}, {point.Y:X})";
	}

	internal static TField ToElement<TField>(BigInteger value) where TField : unmanaged, IECField<TField>
	{
		if (!TField.TryImport(CurveCase.EncodeInteger(value, TField.ByteLength), out TField element))
		{
			throw new ArgumentOutOfRangeException(nameof(value), value, "The value is not below p.");
		}

		TField.ToMontgomery(in element, out element);
		return element;
	}

	internal static BigInteger FieldValue<TField>(in TField element) where TField : unmanaged, IECField<TField>
	{
		TField.FromMontgomery(in element, out TField plain);
		byte[] bytes = new byte[TField.ByteLength];
		TField.Export(in plain, bytes);
		return ModulusCase.Decode(bytes);
	}
}
