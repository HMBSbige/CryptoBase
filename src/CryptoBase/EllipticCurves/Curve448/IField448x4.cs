namespace CryptoBase.EllipticCurves.Curve448;

// Four elements of the field of p = 2^448 − 2^224 − 1, one in each lane A, B, C, D, with the conversions and the ladder step that Curve448Vector takes. Each implementation holds an element in sixteen limbs of radix 2^28 and bounds them: a value is reduced if every limb is below 2^28 + 2^9, as every member that gives a value leaves it. None branches on or indexes by a value; masks are 0 or ulong.MaxValue.
internal interface IField448x4<TSelf> where TSelf : unmanaged, IField448x4<TSelf>
{
	static abstract bool IsSupported { get; }

	// (a, b, c, d), reduced, for elements with limbs below 2^57.
	static abstract void Create(in Field448 a, in Field448 b, in Field448 c, in Field448 d, out TSelf result);

	// The four lanes of a value with limbs below 2^32, carried: limbs below 2^56 except L0 and L4, below 2^56 + 2^5.
	static abstract void Extract(in TSelf value, out Field448 a, out Field448 b, out Field448 c, out Field448 d);

	// The number of values that the multiplier of the ladder takes.
	static abstract int MultiplierLength { get; }

	static abstract ulong LaneALimb(in TSelf value, int limb);

	static abstract void AddFactor(Span<ulong> factors, int limb, int column, ulong term);

	// The multiplier of the ladder from u, which must have limbs below 2^57, in MultiplierLength values: (1, 1, 1, u) in whatever form LadderStep takes it. f_ik is the sum of u_j·c over j, where c is how many times 2^(28(i + j)) counts column k once reduced: 2^(28s) for 16 ≤ s < 24 is 2^(28(s − 8)) + 2^(28(s − 16)) and for s ≥ 24 is 2·2^(28(s − 16)) + 2^(28(s − 24)). Each factor is at most 3·max u_j, below 2^30 for a reduced u.
	static virtual void CreateMultiplier(in Field448 u, Span<TSelf> multiplier)
	{
		Debug.Assert(multiplier.Length == TSelf.MultiplierLength);

		TSelf.Create(in u, in u, in u, in u, out TSelf limbs);
		Span<ulong> factors = MemoryMarshal.Cast<TSelf, ulong>(multiplier);
		factors.Clear();

		for (int i = 0; i < 16; ++i)
		{
			for (int j = 0; j < 16; ++j)
			{
				ulong term = TSelf.LaneALimb(in limbs, j);
				int s = i + j;

				if (s < 16)
				{
					TSelf.AddFactor(factors, i, s, term);
				}
				else if (s < 24)
				{
					TSelf.AddFactor(factors, i, s - 8, term);
					TSelf.AddFactor(factors, i, s - 16, term);
				}
				else
				{
					TSelf.AddFactor(factors, i, s - 16, 2 * term);
					TSelf.AddFactor(factors, i, s - 24, term);
				}
			}
		}

		limbs.ZeroMemory();
	}

	// The number of values of scratch that LadderStep takes.
	static abstract int ScratchLength { get; }

	// One step of the ladder of RFC 7748 §5 on a reduced state (x2, z2, x3, z3), first swapped to (x3, z3, x2, z2) where swap is set, which is 0 or ulong.MaxValue: with A = x2 + z2, B = x2 − z2, C = x3 + z3, D = x3 − z3, AA = A², BB = B² and E = AA − BB, the state becomes (AA·BB, E·(AA + a24·E), (DA + CB)², u·(DA − CB)²), reduced. multiplier is the first of the values of CreateMultiplier and scratch the first of ScratchLength values, which the step overwrites.
	static abstract void LadderStep(ref TSelf state, ulong swap, in TSelf multiplier, ref TSelf scratch);

	// Swaps (A, B) with (C, D) where mask is set.
	static abstract void ConditionalSwapHalves(ulong mask, ref TSelf value);
}
