using CryptoBase.EllipticCurves.Curve448;

namespace CryptoBase.Tests.EllipticCurves.Curve448;

public abstract class Field448VectorCase : IKernelCase
{
	public static IEnumerable<Field448VectorCase> All()
	{
		yield return new Case<Field448x4Avx2>();
		yield return new Case<Field448x4Avx512>();
		yield return new Case<Field448x4AdvSimd>();
		yield return new Case<Field448x4Sse41>();
	}

	public abstract Type FieldType { get; }

	public abstract bool IsSupported { get; }

	internal abstract TResult Accept<TResult>(IField448VectorVisitor<TResult> visitor);

	public override string ToString()
	{
		return FieldType.Name;
	}

	private sealed class Case<TField> : Field448VectorCase where TField : unmanaged, IEdwardsField448x4<TField>
	{
		public override Type FieldType => typeof(TField);

		public override bool IsSupported => TField.IsSupported;

		internal override TResult Accept<TResult>(IField448VectorVisitor<TResult> visitor)
		{
			return visitor.Visit<TField>();
		}
	}
}

internal interface IField448VectorVisitor<out TResult>
{
	TResult Visit<TField>() where TField : unmanaged, IEdwardsField448x4<TField>;
}
