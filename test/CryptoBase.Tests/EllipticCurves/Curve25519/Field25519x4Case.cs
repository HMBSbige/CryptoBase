using CryptoBase.EllipticCurves.Curve25519;

namespace CryptoBase.Tests.EllipticCurves.Curve25519;

// An implementation of IField25519x4 under test, which a visitor reaches with its type.
public abstract class Field25519x4Case : IKernelCase
{
	public static IEnumerable<Field25519x4Case> All()
	{
		yield return new Case<Field25519x4Avx2>();
		yield return new Case<Field25519x4Sse41>();
	}

	public abstract Type FieldType { get; }

	public abstract bool IsSupported { get; }

	internal abstract TResult Accept<TResult>(IField25519x4Visitor<TResult> visitor);

	public override string ToString()
	{
		return FieldType.Name;
	}

	private sealed class Case<TField> : Field25519x4Case where TField : unmanaged, IField25519x4<TField>
	{
		public override Type FieldType => typeof(TField);

		public override bool IsSupported => TField.IsSupported;

		internal override TResult Accept<TResult>(IField25519x4Visitor<TResult> visitor)
		{
			return visitor.Visit<TField>();
		}
	}
}

internal interface IField25519x4Visitor<out TResult>
{
	TResult Visit<TField>() where TField : unmanaged, IField25519x4<TField>;
}
