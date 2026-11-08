using CryptoBase.EllipticCurves.SM9;

namespace CryptoBase.Tests.EllipticCurves.SM9;

public abstract class SM9LanesCase : IKernelCase
{
	public static IEnumerable<SM9LanesCase> All()
	{
		yield return new Case<SM9VectorAvx512>();
		yield return new Case<SM9VectorAvx2>();
		yield return new Case<SM9VectorSse41>();
		yield return new Case<SM9VectorAdvSimd>();
	}

	// The vectors of a whole row, which take the doubling step in lanes.
	public static IEnumerable<SM9LanesCase> Rows()
	{
		return All().Where(static vector => vector.FillsRow);
	}

	public abstract Type VectorType { get; }

	public abstract bool IsSupported { get; }

	public abstract bool FillsRow { get; }

	internal abstract TResult Accept<TResult>(ISM9LanesVisitor<TResult> visitor);

	public override string ToString()
	{
		return VectorType.Name;
	}

	private sealed class Case<TVector> : SM9LanesCase where TVector : unmanaged, ISM9Vector<TVector>
	{
		public override Type VectorType => typeof(TVector);

		public override bool IsSupported => TVector.IsSupported;

		public override bool FillsRow => TVector.Count == SM9Lanes<TVector>.RowLength;

		internal override TResult Accept<TResult>(ISM9LanesVisitor<TResult> visitor)
		{
			return visitor.Visit<TVector>();
		}
	}
}

internal interface ISM9LanesVisitor<out TResult>
{
	TResult Visit<TVector>() where TVector : unmanaged, ISM9Vector<TVector>;
}
