namespace CryptoBase.EllipticCurves.Curve448;

// The ladder of X448, four field elements at a time.
internal static class Curve448Vector<TField> where TField : unmanaged, IField448x4<TField>
{
	internal const int ScalarLength = 56;

	private const int LimbCount = ScalarLength / sizeof(ulong);

	// Each step takes the bit of k from 447 down to 0. The values start on a 64-byte line: the stack aligns locals to 16 bytes at most, and the writes of a vector that straddles a line do not forward to the reads of the next product.
	[SkipLocalsInit]
	internal static void Ladder(ReadOnlySpan<byte> scalar, in Field448 u, out Field448 x, out Field448 z)
	{
		Debug.Assert(scalar.Length is ScalarLength);

		Span<ulong> limbs = stackalloc ulong[LimbCount];
		int count = 1 + TField.MultiplierLength + TField.ScratchLength;
		Span<byte> storage = stackalloc byte[AlignedScratch.StorageLength<TField>(count)];
		Span<TField> values = AlignedScratch.Align<TField>(storage, count);
		ref TField state = ref values[0];
		ref TField multiplier = ref values[1];
		ref TField scratch = ref values[1 + TField.MultiplierLength];

		for (int i = 0; i < limbs.Length; ++i)
		{
			limbs[i] = BinaryPrimitives.ReadUInt64LittleEndian(scalar.Slice(8 * i));
		}

		Field448 zero = default;
		Field448 one = default;
		one.L0 = 1;
		TField.Create(in one, in zero, in u, in one, out state);
		TField.CreateMultiplier(in u, values.Slice(1, TField.MultiplierLength));
		ulong swap = 0;

		for (int t = 8 * ScalarLength - 1; t >= 0; --t)
		{
			ulong bit = limbs[t >> 6] >> (t & 63) & 1;
			swap ^= bit;
			TField.LadderStep(ref state, 0 - swap, in multiplier, ref scratch);
			swap = bit;
		}

		TField.ConditionalSwapHalves(0 - swap, ref state);
		TField.Extract(in state, out x, out z, out Field448 x3, out Field448 z3);
		limbs.ZeroMemory();
		storage.ZeroMemory();
		x3.ZeroMemory();
		z3.ZeroMemory();
	}
}
