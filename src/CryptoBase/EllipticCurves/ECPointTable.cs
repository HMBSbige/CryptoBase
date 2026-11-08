namespace CryptoBase.EllipticCurves;

// The windows of ECGeneratorTable for a public point P in place of G, so that ECGroup.MultiplyBaseAndFixed gives k·P from them as ECGroup.MultiplyBase gives k·G. The table does not change once built, so threads may share it.
internal sealed class ECPointTable<TCurve, TField, TOrder>
	where TCurve : struct, IECCurve
	where TField : unmanaged, IECField<TField>
	where TOrder : unmanaged, IMontgomeryModulus
{
	// Pinned, from ECGeneratorTable.Build.
	private readonly ulong[] _storage;
	private readonly int _start;

	// For a point on the curve, which is public, so the build may take variable time.
	internal ECPointTable(in AffinePoint<TField> point)
	{
		_storage = ECGeneratorTable<TCurve, TField, TOrder>.Build(in point);
		_start = ECGeneratorTable<TCurve, TField, TOrder>.AlignedStart(_storage);
	}

	internal ReadOnlySpan<ulong> Windows => new(_storage, _start, ECGeneratorTable<TCurve, TField, TOrder>.Length);
}
