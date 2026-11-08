using CryptoBase.EllipticCurves;

namespace CryptoBase.Tests.EllipticCurves;

public abstract class SM2Field29LanesCase : IKernelCase
{
	public static IEnumerable<SM2Field29LanesCase> All()
	{
		yield return new Case<SM2Field29x8Avx512>();
		yield return new Case<SM2Field29x4Avx2>();
		yield return new Case<SM2Field29x2Sse41>();
		yield return new Case<SM2Field29x2AdvSimd>();
	}

	public abstract Type FieldType { get; }

	public abstract bool IsSupported { get; }

	internal abstract TResult Accept<TResult>(ISM2Field29LanesVisitor<TResult> visitor);

	public override string ToString()
	{
		return FieldType.Name;
	}

	private sealed class Case<TField> : SM2Field29LanesCase where TField : unmanaged, ISM2Field29Lanes<TField>
	{
		public override Type FieldType => typeof(TField);

		public override bool IsSupported => TField.IsSupported;

		internal override TResult Accept<TResult>(ISM2Field29LanesVisitor<TResult> visitor)
		{
			return visitor.Visit<TField>();
		}
	}
}

internal interface ISM2Field29LanesVisitor<out TResult>
{
	TResult Visit<TField>() where TField : unmanaged, ISM2Field29Lanes<TField>;
}
