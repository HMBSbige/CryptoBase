namespace CryptoBase.Tests.EllipticCurves;

internal static class ECTestUtils
{
	internal static void CheckPoint(List<string> failures, ECReference reference, string operation, JacobianValue actual, CurvePoint? expected)
	{
		if (!reference.IsOnJacobianCurve(actual))
		{
			failures.Add($"{operation} gave {actual}, which is not on the curve");
		}
		else if (reference.ToAffine(actual) != expected)
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
}
