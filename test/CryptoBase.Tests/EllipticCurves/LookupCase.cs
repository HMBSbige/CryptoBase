using CryptoBase.EllipticCurves;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace CryptoBase.Tests.EllipticCurves;

public abstract class LookupCase
{
	public static IEnumerable<LookupCase> All()
	{
		return Widths<AffinePoint<P256Field>>()
			.Concat(Widths<AffinePoint<P384Field>>())
			.Concat(Widths<AffinePoint<P521Field>>())
			.Concat(Widths<ProjectivePoint<P256Field>>())
			.Concat(Widths<ProjectivePoint<P384Field>>())
			.Concat(Widths<ProjectivePoint<P521Field>>());
	}

	public static IEnumerable<Type> WidthTypes()
	{
		return All().Select(static lookup => lookup.WidthType).OfType<Type>().Distinct();
	}

	// The ILimbVector type, or null for the dispatch.
	public abstract Type? WidthType { get; }

	public abstract Type EntryType { get; }

	public abstract int EntryLength { get; }

	// result is filled with filler first, to show the bytes that Lookup leaves.
	internal abstract byte[] Lookup(ReadOnlySpan<byte> table, int count, uint index, byte filler);

	public override string ToString()
	{
		return $"{EntryType.Name}<{EntryType.GetGenericArguments()[0].Name}> in {WidthType?.Name ?? "dispatch"}";
	}

	private static IEnumerable<LookupCase> Widths<T>() where T : unmanaged
	{
		yield return new Case<T, LimbScalar>();
		yield return new Case<T, LimbVector128>();
		yield return new Case<T, LimbVector256>();
		yield return new Case<T, LimbVector512>();
		yield return new Dispatch<T>();
	}

	private abstract class Entries<T> : LookupCase where T : unmanaged
	{
		public override Type EntryType => typeof(T);

		public override int EntryLength => Unsafe.SizeOf<T>();

		internal override byte[] Lookup(ReadOnlySpan<byte> table, int count, uint index, byte filler)
		{
			T result = default;
			Span<byte> bytes = MemoryMarshal.AsBytes(new Span<T>(ref result));
			bytes.Fill(filler);
			Lookup(in MemoryMarshal.AsRef<T>(table), count, index, out result);
			return bytes.ToArray();
		}

		private protected abstract void Lookup(ref readonly T table, int count, uint index, out T result);
	}

	private sealed class Case<T, TVector> : Entries<T> where T : unmanaged where TVector : struct, ILimbVector<TVector>
	{
		public override Type WidthType => typeof(TVector);

		private protected override void Lookup(ref readonly T table, int count, uint index, out T result)
		{
			MaskedSelect.Lookup<T, TVector>(in table, count, index, out result);
		}
	}

	private sealed class Dispatch<T> : Entries<T> where T : unmanaged
	{
		public override Type? WidthType => null;

		private protected override void Lookup(ref readonly T table, int count, uint index, out T result)
		{
			MaskedSelect.Lookup(in table, count, index, out result);
		}
	}
}
