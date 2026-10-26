namespace CryptoBase.EllipticCurves;

// Window i holds j·2^(wi)·G for j from 1 to 2^(w − 1), w = GeneratorWindowWidth, each entry as TField.Pack writes it. The entries start on a 64-byte boundary, so that a 64-byte entry fills one cache line.
internal static class EcGeneratorTable<TCurve, TField, TOrder>
	where TCurve : struct, IEcCurve
	where TField : unmanaged, IEcField<TField>
	where TOrder : unmanaged, IMontgomeryModulus
{
	private const int Alignment = 64;

	// Pinned, so that the boundary stays where Start finds it.
	// ReSharper disable once StaticMemberInGenericType
	private static readonly ulong[] Storage = Build();

	// ReSharper disable once StaticMemberInGenericType
	private static readonly int Start = AlignedStart(Storage);

	internal static int WindowCount => EcGroup<TCurve, TField, TOrder>.DigitCount(TCurve.GeneratorWindowWidth);

	internal static int WindowLength => 1 << TCurve.GeneratorWindowWidth - 1;

	internal static int EntryLength => 2 * TField.PackedLength;

	internal static ref readonly ulong Window(int index)
	{
		return ref Unsafe.Add(ref MemoryMarshal.GetArrayDataReference(Storage), Start + index * WindowLength * EntryLength);
	}

	// index counts entries across the windows and must be public, as the address read depends on it.
	internal static void Read(int index, out AffinePoint<TField> result)
	{
		Unsafe.SkipInit(out result);
		MemoryMarshal.CreateReadOnlySpan(in Unsafe.Add(ref Unsafe.AsRef(in Window(0)), index * EntryLength), EntryLength).CopyTo(MemoryMarshal.Cast<AffinePoint<TField>, ulong>(new Span<AffinePoint<TField>>(ref result)));
		TField.Unpack(ref result);
	}

	// The base B of a window doubles into 2B, and each later entry j·B, j ≥ 3, is (j − 1)·B + B, two points that are neither equal, opposite nor at infinity.
	private static ulong[] Build()
	{
		Debug.Assert(WindowLength >= 2);

		JacobianPoint<TField>[] multiples = new JacobianPoint<TField>[WindowCount * WindowLength];
		EcGroup<TCurve, TField, TOrder>.Generator(out AffinePoint<TField> generator);
		JacobianPoint<TField>.FromAffine(in generator, out JacobianPoint<TField> windowBase);

		for (int i = 0; i < multiples.Length; i += WindowLength)
		{
			multiples[i] = windowBase;
			EcGroup<TCurve, TField, TOrder>.Double(in windowBase, out multiples[i + 1]);

			for (int j = 2; j < WindowLength; ++j)
			{
				_ = EcGroup<TCurve, TField, TOrder>.AddDistinct(in multiples[i + j - 1], in windowBase, out multiples[i + j]);
			}

			// The last entry is 2^(w − 1) times the base, so its double is the base of the next window.
			EcGroup<TCurve, TField, TOrder>.Double(in multiples[i + WindowLength - 1], out windowBase);
		}

		AffinePoint<TField>[] entries = new AffinePoint<TField>[multiples.Length];
		EcGroup<TCurve, TField, TOrder>.ToAffineVariableTime(multiples, entries);
		ulong[] storage = GC.AllocateUninitializedArray<ulong>(entries.Length * EntryLength + Alignment / sizeof(ulong) - 1, true);
		Span<ulong> packed = storage.AsSpan(AlignedStart(storage));

		for (int i = 0; i < entries.Length; ++i)
		{
			TField.Pack(in entries[i], packed.Slice(i * EntryLength, EntryLength));
		}

		return storage;
	}

	// Array data is aligned to its 8-byte elements, so the boundary falls on a whole limb.
	private static int AlignedStart(ulong[] storage)
	{
		nint address = Marshal.UnsafeAddrOfPinnedArrayElement(storage, 0);
		return (int)(-address & Alignment - 1) / sizeof(ulong);
	}
}
