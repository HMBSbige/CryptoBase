namespace CryptoBase.EllipticCurves.Curve448;

// The ladder of X448, four field elements at a time.
internal static class Curve448Vector<TField> where TField : unmanaged, IField448x4<TField>
{
	// Each step takes the bit of k from 447 down to 0. The values start on a 64-byte line: the stack aligns locals to 16 bytes at most, and the writes of a vector that straddles a line do not forward to the reads of the next product.
	[SkipLocalsInit]
	internal static void Ladder(ReadOnlySpan<byte> scalar, in Field448 u, out Field448 x, out Field448 z)
	{
		Debug.Assert(scalar.Length is ScalarDigits.LimbCount * sizeof(ulong));

		Span<ulong> limbs = stackalloc ulong[ScalarDigits.LimbCount];
		int count = 1 + TField.MultiplierLength + TField.ScratchLength;
		Span<byte> storage = stackalloc byte[AlignedScratch.StorageLength<TField>(count)];
		Span<TField> values = AlignedScratch.Align<TField>(storage, count);
		ref TField state = ref values[0];
		ref TField multiplier = ref values[1];
		ref TField scratch = ref values[1 + TField.MultiplierLength];
		ScalarDigits.ReadLimbs(scalar, limbs);
		Field448 zero = default;
		TField.Create(in Field448.One, in zero, in u, in Field448.One, out state);
		TField.CreateMultiplier(in u, values.Slice(1, TField.MultiplierLength));
		ulong swap = 0;

		for (int t = 447; t >= 0; --t)
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
