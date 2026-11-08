using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.EllipticCurves;

// k·P and u1·G + u2·Q for one point at a time on the four lanes of SM2Field29x4Avx2, which AVX2 runs, and AVX-512 for u1·G + u2·Q and the doublings, the table and the sum of SM2OctoFormulas: each round of a formula takes up to four products that need only those of the rounds before, one in each lane. Doubling for a = −3 with δ = Z², γ = Y² and α = 3(X − δ)(X + δ) gives X3 = α² − 8Xγ, Y3 = γ(12αX − 8γ) − α³, Z3 = 2YZ and δ3 = 4γδ, from which α3 needs one more product; a state carries α with the point, so that two doublings take five rounds and a window of ECGroup.Multiply, five doublings and an addition whose last round also gives the α of the next window, sixteen. A state holds P = [α, Y, X, Z] and Q = [X, δ, ·, α], an entry EA = [Z², X, Y, Z] and EB = [X, Z², Z³, Z³]; [a, b, c, d] holds a in lane 0 to d in lane 3, lanes 0 and 1 and lanes 2 and 3 sharing a half of 128 bits, which the unpacks and Shuffle stay within and Permute4x64 crosses, and a lane that no later step reads may hold anything.
// Bounds, with those of SM2Field29: a state has X below 2p in limbs below 3·2^29 + 2^22, limb 8 below 2^24 + 2^5, Y below 4p in limbs below 2^30, limb 8 below 2^26 + 2, Z below 2.7p in limbs below 2^30 + 2^8, δ a product below 1.25p and α a product below 2.9p, or the coordinates of an entry: X, Y and Z as Reduce leaves them, Y negated as 4p − Y or not, and Z² and Z³ products, which joining limbs 2m and 2m + 1 into one ulong and splitting them again leaves in limbs at most 1 above those of a product. Every product stays below 3.2p, its limb 8 below 2^26 − 2, so that every subtrahend, a product, a sum of up to three products or a coordinate that Reduce left, has limbs at most those of the 4p, 8p or 12p added to it, and a product plus 4p less a product has limbs below 3·2^29 + 2^6. Such a difference goes into a product only against a product, a coordinate that Reduce left or a value carried by one step, each limb but limb 8 keeping its low 29 bits and passing the rest to the limb above, which leaves limbs below 2^29 + 2^4 for limbs below 2^33. A fold takes a difference a + 4p − b of products, a value below 7.2p, with FourPFold2 and FourPFold3 in place of limbs 2 and 3 of the 4p, to that value less h·p for h = L8 >> 24: it takes h·2^24 off limb 8 and h·2^6 off limb 2, which FourPFold2 keeps at least 2^29 + 190 before, and adds h to limb 0, h·2^9 to limb 3 and h·2^21 to limb 7, whose limb of 4p is 2^23 below the others, so that limb 8 is below 2^24, every limb below 3·2^29 + 2^23, and below 3·2^29 + 2^22 for the values below 5.3p that the folds of X take, and the value below p + 2^235. With the bounds of each formula below, the limbs of the operands of every product have bounds whose product is below 7.1·2^58, as Multiply takes them, and every input of Reduce has limbs below 7·2^29 + 2^6.
internal static class SM2QuadFormulas
{
	// The windows of ECGroup.Multiply, whose digits Recode gives.
	private const int WindowWidth = 5;

	private const int TableLength = 1 << WindowWidth - 1;

	// The entries in the layout of SM2PairFormulas: [X | Y] and [Z³ | Z], limbs 2m and 2m + 1 joined into one ulong for m from 0 to 3 and limb 8 alone, the lanes interleaved, and then Z².
	private const int EntryLength = 25;

	private const int CubeOffset = 10;

	private const int SquareOffset = 20;

	// The NAF of u2 in ECVariableTimeGroup.MultiplyAdd, over Q, 3Q, …, 15Q.
	private const int PointWidth = 5;

	private const int OddLength = 1 << PointWidth - 2;

	private const int LaneCount = 4;

	// The windows of ECGroup.Multiply on the table of BuildTable: a window is two DoubleTwice and a DoubleAdd. The points of an addition are neither equal nor opposite except where the masks cover them and in window 0 for k = n − 6, where they are equal and the double takes the place of the sum. Neither the time nor the addresses depend on k or P, and the intermediates are cleared.
	[SkipLocalsInit]
	internal static void Multiply(in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		Span<sbyte> digits = stackalloc sbyte[ECGroup<SM2Curve, SM2Field52, SM2Order>.DigitCount(WindowWidth)];
		Span<ulong> table = stackalloc ulong[TableLength * EntryLength];
		Span<ulong> packed = stackalloc ulong[EntryLength];
		Span<ulong> masks = stackalloc ulong[4 * LaneCount];
		Span<ulong> zero = masks.Slice(0, LaneCount);
		Span<ulong> infinity = masks.Slice(LaneCount, LaneCount);
		Span<ulong> negative = masks.Slice(2 * LaneCount, LaneCount);
		Span<ulong> equal = masks.Slice(3 * LaneCount, LaneCount);
		ECGroup<SM2Curve, SM2Field52, SM2Order>.Recode(in scalar, WindowWidth, digits);
		BuildTable(in point, table);
		Unsafe.SkipInit(out SM2QuadEntry entry);
		Unsafe.SkipInit(out SM2QuadState state);
		Unsafe.SkipInit(out SM2QuadState twice);
		Select(table, digits[^1], packed, negative, out entry);
		FromEntry(in entry, out state);
		// A lane mask is set in every lane. The sum is the point at infinity just while every digit so far is 0, which the masks track instead of Z.
		infinity.Fill(ZeroMask((ulong)digits[^1]));
		ReadOnlySpan<ulong> limbs = FieldElement<SM2Order>.GetLimbs(in scalar);
		ReadOnlySpan<ulong> n = SM2Order.Modulus;
		equal.Fill(ZeroMask(limbs[0] ^ n[0] - 6 | limbs[1] ^ n[1] | limbs[2] ^ n[2] | limbs[3] ^ n[3]));

		for (int i = digits.Length - 2; i >= 0; --i)
		{
			DoubleTwice(ref state);
			DoubleTwice(ref state);

			if (i is 0)
			{
				twice = state;
				DoubleTwice(ref twice);
			}

			Select(table, digits[i], packed, negative, out entry);
			zero.Fill(ZeroMask((ulong)digits[i]));
			DoubleAdd(ref state, in entry, in zero[0], in infinity[0]);

			for (int lane = 0; lane < LaneCount; ++lane)
			{
				infinity[lane] &= zero[lane];
			}
		}

		SM2QuadState.ConditionalSelect(in equal[0], in twice, in state, out state);
		// The point at infinity, for k = 0, comes out as (0, 0, 0), as from ECGroup.Multiply.
		ToJacobian(in state, out result);
		JacobianPoint<SM2Field52> cleared = default;
		JacobianPoint<SM2Field52>.ConditionalSelect(infinity[0], in cleared, in result, out result);
		digits.ZeroMemory();
		table.ZeroMemory();
		packed.ZeroMemory();
		masks.ZeroMemory();
		entry.ZeroMemory();
		state.ZeroMemory();
		twice.ZeroMemory();
	}

	// Writes j·P to entry j − 1 of the table in the layout of SM2PairFormulas.BuildTable: 2j·P = 2·(j·P) by DoubleOnce and (2j + 1)·P = 2j·P + P by AddState, an addition of points neither equal nor opposite, as 2j ± 1 < n. Neither the time nor the addresses depend on P, and the intermediates are cleared.
	[SkipLocalsInit]
	internal static void BuildTable(in AffinePoint<SM2Field52> point, Span<ulong> table)
	{
		Debug.Assert(table.Length == TableLength * EntryLength);

		Span<SM2QuadState> multiples = stackalloc SM2QuadState[TableLength];
		ToEntry(in point, out SM2QuadEntry entry);
		FromEntry(in entry, out multiples[0]);

		for (int j = 2; j <= TableLength; ++j)
		{
			if (j % 2 is 0)
			{
				multiples[j - 1] = multiples[j / 2 - 1];
				DoubleOnce(ref multiples[j - 1]);
			}
			else
			{
				multiples[j - 1] = multiples[j - 2];
				AddState(ref multiples[j - 1], in entry);
			}
		}

		for (int j = 0; j < TableLength; j += LaneCount)
		{
			Pack(multiples.Slice(j, LaneCount), table.Slice(j * EntryLength, LaneCount * EntryLength));
		}

		multiples.ZeroMemory();
		entry.ZeroMemory();
	}

	// Four states as entries of EntryLength limbs, with X, Y and Z as Reduce leaves them, Z² the δ of the state and Z³ = Z·δ, a product for all four in one round. Joining limbs 2m and 2m + 1 of a product adds the bits of limb 2m from 29 up to limb 2m + 1, at most 1, which splitting them again leaves there.
	[SkipLocalsInit]
	internal static void Pack(Span<SM2QuadState> states, Span<ulong> destination)
	{
		Unsafe.SkipInit(out SM2Field29x4Avx2 left);
		Unsafe.SkipInit(out SM2Field29x4Avx2 right);

		for (int k = 0; k < LaneCount; ++k)
		{
			SM2Field29x4Avx2.Reduce(in states[k].P, out states[k].P);
		}

		ref SM2QuadState a = ref states[0];
		ref SM2QuadState b = ref states[1];
		ref SM2QuadState c = ref states[2];
		ref SM2QuadState d = ref states[3];
		left.L0 = Avx2.Permute2x128(Avx2.UnpackHigh(a.P.L0, b.P.L0), Avx2.UnpackHigh(c.P.L0, d.P.L0), 0x31);
		right.L0 = Avx2.Permute2x128(Avx2.UnpackHigh(a.Q.L0, b.Q.L0), Avx2.UnpackHigh(c.Q.L0, d.Q.L0), 0x20);
		left.L1 = Avx2.Permute2x128(Avx2.UnpackHigh(a.P.L1, b.P.L1), Avx2.UnpackHigh(c.P.L1, d.P.L1), 0x31);
		right.L1 = Avx2.Permute2x128(Avx2.UnpackHigh(a.Q.L1, b.Q.L1), Avx2.UnpackHigh(c.Q.L1, d.Q.L1), 0x20);
		left.L2 = Avx2.Permute2x128(Avx2.UnpackHigh(a.P.L2, b.P.L2), Avx2.UnpackHigh(c.P.L2, d.P.L2), 0x31);
		right.L2 = Avx2.Permute2x128(Avx2.UnpackHigh(a.Q.L2, b.Q.L2), Avx2.UnpackHigh(c.Q.L2, d.Q.L2), 0x20);
		left.L3 = Avx2.Permute2x128(Avx2.UnpackHigh(a.P.L3, b.P.L3), Avx2.UnpackHigh(c.P.L3, d.P.L3), 0x31);
		right.L3 = Avx2.Permute2x128(Avx2.UnpackHigh(a.Q.L3, b.Q.L3), Avx2.UnpackHigh(c.Q.L3, d.Q.L3), 0x20);
		left.L4 = Avx2.Permute2x128(Avx2.UnpackHigh(a.P.L4, b.P.L4), Avx2.UnpackHigh(c.P.L4, d.P.L4), 0x31);
		right.L4 = Avx2.Permute2x128(Avx2.UnpackHigh(a.Q.L4, b.Q.L4), Avx2.UnpackHigh(c.Q.L4, d.Q.L4), 0x20);
		left.L5 = Avx2.Permute2x128(Avx2.UnpackHigh(a.P.L5, b.P.L5), Avx2.UnpackHigh(c.P.L5, d.P.L5), 0x31);
		right.L5 = Avx2.Permute2x128(Avx2.UnpackHigh(a.Q.L5, b.Q.L5), Avx2.UnpackHigh(c.Q.L5, d.Q.L5), 0x20);
		left.L6 = Avx2.Permute2x128(Avx2.UnpackHigh(a.P.L6, b.P.L6), Avx2.UnpackHigh(c.P.L6, d.P.L6), 0x31);
		right.L6 = Avx2.Permute2x128(Avx2.UnpackHigh(a.Q.L6, b.Q.L6), Avx2.UnpackHigh(c.Q.L6, d.Q.L6), 0x20);
		left.L7 = Avx2.Permute2x128(Avx2.UnpackHigh(a.P.L7, b.P.L7), Avx2.UnpackHigh(c.P.L7, d.P.L7), 0x31);
		right.L7 = Avx2.Permute2x128(Avx2.UnpackHigh(a.Q.L7, b.Q.L7), Avx2.UnpackHigh(c.Q.L7, d.Q.L7), 0x20);
		left.L8 = Avx2.Permute2x128(Avx2.UnpackHigh(a.P.L8, b.P.L8), Avx2.UnpackHigh(c.P.L8, d.P.L8), 0x31);
		right.L8 = Avx2.Permute2x128(Avx2.UnpackHigh(a.Q.L8, b.Q.L8), Avx2.UnpackHigh(c.Q.L8, d.Q.L8), 0x20);
		SM2Field29x4Avx2.Multiply(in left, in right, out SM2Field29x4Avx2 cubes);

		for (int k = 0; k < LaneCount; ++k)
		{
			ref SM2QuadState state = ref states[k];
			ref ulong entry = ref destination[k * EntryLength];
			Vector256<ulong> p0 = state.P.L0 + (state.P.L1 << SM2Field29.Bits);
			Vector256<ulong> q0 = state.Q.L0 + (state.Q.L1 << SM2Field29.Bits);
			Vector256<ulong> z0 = cubes.L0 + (cubes.L1 << SM2Field29.Bits);
			Unsafe.Add(ref entry, 0) = p0.GetElement(2);
			Unsafe.Add(ref entry, 1) = p0.GetElement(1);
			Unsafe.Add(ref entry, CubeOffset + 0) = z0.GetElement(k);
			Unsafe.Add(ref entry, CubeOffset + 1) = p0.GetElement(3);
			Unsafe.Add(ref entry, SquareOffset + 0) = q0.GetElement(1);
			Vector256<ulong> p1 = state.P.L2 + (state.P.L3 << SM2Field29.Bits);
			Vector256<ulong> q1 = state.Q.L2 + (state.Q.L3 << SM2Field29.Bits);
			Vector256<ulong> z1 = cubes.L2 + (cubes.L3 << SM2Field29.Bits);
			Unsafe.Add(ref entry, 2) = p1.GetElement(2);
			Unsafe.Add(ref entry, 3) = p1.GetElement(1);
			Unsafe.Add(ref entry, CubeOffset + 2) = z1.GetElement(k);
			Unsafe.Add(ref entry, CubeOffset + 3) = p1.GetElement(3);
			Unsafe.Add(ref entry, SquareOffset + 1) = q1.GetElement(1);
			Vector256<ulong> p2 = state.P.L4 + (state.P.L5 << SM2Field29.Bits);
			Vector256<ulong> q2 = state.Q.L4 + (state.Q.L5 << SM2Field29.Bits);
			Vector256<ulong> z2 = cubes.L4 + (cubes.L5 << SM2Field29.Bits);
			Unsafe.Add(ref entry, 4) = p2.GetElement(2);
			Unsafe.Add(ref entry, 5) = p2.GetElement(1);
			Unsafe.Add(ref entry, CubeOffset + 4) = z2.GetElement(k);
			Unsafe.Add(ref entry, CubeOffset + 5) = p2.GetElement(3);
			Unsafe.Add(ref entry, SquareOffset + 2) = q2.GetElement(1);
			Vector256<ulong> p3 = state.P.L6 + (state.P.L7 << SM2Field29.Bits);
			Vector256<ulong> q3 = state.Q.L6 + (state.Q.L7 << SM2Field29.Bits);
			Vector256<ulong> z3 = cubes.L6 + (cubes.L7 << SM2Field29.Bits);
			Unsafe.Add(ref entry, 6) = p3.GetElement(2);
			Unsafe.Add(ref entry, 7) = p3.GetElement(1);
			Unsafe.Add(ref entry, CubeOffset + 6) = z3.GetElement(k);
			Unsafe.Add(ref entry, CubeOffset + 7) = p3.GetElement(3);
			Unsafe.Add(ref entry, SquareOffset + 3) = q3.GetElement(1);
			Vector256<ulong> p4 = state.P.L8;
			Vector256<ulong> q4 = state.Q.L8;
			Vector256<ulong> z4 = cubes.L8;
			Unsafe.Add(ref entry, 8) = p4.GetElement(2);
			Unsafe.Add(ref entry, 9) = p4.GetElement(1);
			Unsafe.Add(ref entry, CubeOffset + 8) = z4.GetElement(k);
			Unsafe.Add(ref entry, CubeOffset + 9) = p4.GetElement(3);
			Unsafe.Add(ref entry, SquareOffset + 4) = q4.GetElement(1);
		}

		left.ZeroMemory();
		right.ZeroMemory();
		cubes.ZeroMemory();
	}

	// The entry of a state, with X, Y and Z as Reduce leaves them, Z² the δ of the state and Z³ = Z·δ from one product.
	[SkipLocalsInit]
	internal static void ToEntry(in SM2QuadState state, out SM2QuadEntry entry)
	{
		Unsafe.SkipInit(out entry);
		Unsafe.SkipInit(out SM2Field29x4Avx2 left);
		Unsafe.SkipInit(out SM2Field29x4Avx2 right);
		SM2Field29x4Avx2.Reduce(in state.P, out SM2Field29x4Avx2 p);
		left.L0 = Broadcast3(p.L0);
		right.L0 = Broadcast1(state.Q.L0);
		left.L1 = Broadcast3(p.L1);
		right.L1 = Broadcast1(state.Q.L1);
		left.L2 = Broadcast3(p.L2);
		right.L2 = Broadcast1(state.Q.L2);
		left.L3 = Broadcast3(p.L3);
		right.L3 = Broadcast1(state.Q.L3);
		left.L4 = Broadcast3(p.L4);
		right.L4 = Broadcast1(state.Q.L4);
		left.L5 = Broadcast3(p.L5);
		right.L5 = Broadcast1(state.Q.L5);
		left.L6 = Broadcast3(p.L6);
		right.L6 = Broadcast1(state.Q.L6);
		left.L7 = Broadcast3(p.L7);
		right.L7 = Broadcast1(state.Q.L7);
		left.L8 = Broadcast3(p.L8);
		right.L8 = Broadcast1(state.Q.L8);
		SM2Field29x4Avx2.Multiply(in left, in right, out SM2Field29x4Avx2 cubes);
		Vector256<ulong> d0 = Broadcast1(state.Q.L0);
		Vector256<ulong> a0 = Avx2.Permute4x64(p.L0, 0xD8);
		entry.EA.L0 = Blend0(a0, d0);
		entry.EB.L0 = Blend23(Blend1(Broadcast1(a0), d0), cubes.L0);
		Vector256<ulong> d1 = Broadcast1(state.Q.L1);
		Vector256<ulong> a1 = Avx2.Permute4x64(p.L1, 0xD8);
		entry.EA.L1 = Blend0(a1, d1);
		entry.EB.L1 = Blend23(Blend1(Broadcast1(a1), d1), cubes.L1);
		Vector256<ulong> d2 = Broadcast1(state.Q.L2);
		Vector256<ulong> a2 = Avx2.Permute4x64(p.L2, 0xD8);
		entry.EA.L2 = Blend0(a2, d2);
		entry.EB.L2 = Blend23(Blend1(Broadcast1(a2), d2), cubes.L2);
		Vector256<ulong> d3 = Broadcast1(state.Q.L3);
		Vector256<ulong> a3 = Avx2.Permute4x64(p.L3, 0xD8);
		entry.EA.L3 = Blend0(a3, d3);
		entry.EB.L3 = Blend23(Blend1(Broadcast1(a3), d3), cubes.L3);
		Vector256<ulong> d4 = Broadcast1(state.Q.L4);
		Vector256<ulong> a4 = Avx2.Permute4x64(p.L4, 0xD8);
		entry.EA.L4 = Blend0(a4, d4);
		entry.EB.L4 = Blend23(Blend1(Broadcast1(a4), d4), cubes.L4);
		Vector256<ulong> d5 = Broadcast1(state.Q.L5);
		Vector256<ulong> a5 = Avx2.Permute4x64(p.L5, 0xD8);
		entry.EA.L5 = Blend0(a5, d5);
		entry.EB.L5 = Blend23(Blend1(Broadcast1(a5), d5), cubes.L5);
		Vector256<ulong> d6 = Broadcast1(state.Q.L6);
		Vector256<ulong> a6 = Avx2.Permute4x64(p.L6, 0xD8);
		entry.EA.L6 = Blend0(a6, d6);
		entry.EB.L6 = Blend23(Blend1(Broadcast1(a6), d6), cubes.L6);
		Vector256<ulong> d7 = Broadcast1(state.Q.L7);
		Vector256<ulong> a7 = Avx2.Permute4x64(p.L7, 0xD8);
		entry.EA.L7 = Blend0(a7, d7);
		entry.EB.L7 = Blend23(Blend1(Broadcast1(a7), d7), cubes.L7);
		Vector256<ulong> d8 = Broadcast1(state.Q.L8);
		Vector256<ulong> a8 = Avx2.Permute4x64(p.L8, 0xD8);
		entry.EA.L8 = Blend0(a8, d8);
		entry.EB.L8 = Blend23(Blend1(Broadcast1(a8), d8), cubes.L8);
		p.ZeroMemory();
		cubes.ZeroMemory();
	}

	// The state of an entry, with α = (X − Z² + 4p)·3(X + Z²) in lane 0 of one round, the right carried: X − Z² + 4p is below 6p in limbs below 3·2^29, and 3(X + Z²), below 9.8p in limbs below 6·2^29 + 2^8, goes in carried, in limbs below 2^29 + 2^3, so α is below 2.9p.
	[SkipLocalsInit]
	internal static void FromEntry(in SM2QuadEntry entry, out SM2QuadState state)
	{
		Unsafe.SkipInit(out state);
		Unsafe.SkipInit(out SM2Field29x4Avx2 left);
		Unsafe.SkipInit(out SM2Field29x4Avx2 right);
		Vector256<ulong> b0 = entry.EB.L0;
		Vector256<ulong> s0 = Swap(b0);
		Vector256<ulong> t0 = b0 + s0;
		left.L0 = b0 + Vector256.Create(SM2Field29.FourP0) - s0;
		Vector256<ulong> m0 = t0 + (t0 << 1);
		right.L0 = m0 & Vector256.Create(SM2Field29.Mask);
		Vector256<ulong> b1 = entry.EB.L1;
		Vector256<ulong> s1 = Swap(b1);
		Vector256<ulong> t1 = b1 + s1;
		left.L1 = b1 + Vector256.Create(SM2Field29.FourP1) - s1;
		Vector256<ulong> m1 = t1 + (t1 << 1);
		right.L1 = (m1 & Vector256.Create(SM2Field29.Mask)) + (m0 >> SM2Field29.Bits);
		Vector256<ulong> b2 = entry.EB.L2;
		Vector256<ulong> s2 = Swap(b2);
		Vector256<ulong> t2 = b2 + s2;
		left.L2 = b2 + Vector256.Create(SM2Field29.FourP2) - s2;
		Vector256<ulong> m2 = t2 + (t2 << 1);
		right.L2 = (m2 & Vector256.Create(SM2Field29.Mask)) + (m1 >> SM2Field29.Bits);
		Vector256<ulong> b3 = entry.EB.L3;
		Vector256<ulong> s3 = Swap(b3);
		Vector256<ulong> t3 = b3 + s3;
		left.L3 = b3 + Vector256.Create(SM2Field29.FourP3) - s3;
		Vector256<ulong> m3 = t3 + (t3 << 1);
		right.L3 = (m3 & Vector256.Create(SM2Field29.Mask)) + (m2 >> SM2Field29.Bits);
		Vector256<ulong> b4 = entry.EB.L4;
		Vector256<ulong> s4 = Swap(b4);
		Vector256<ulong> t4 = b4 + s4;
		left.L4 = b4 + Vector256.Create(SM2Field29.FourPMiddle) - s4;
		Vector256<ulong> m4 = t4 + (t4 << 1);
		right.L4 = (m4 & Vector256.Create(SM2Field29.Mask)) + (m3 >> SM2Field29.Bits);
		Vector256<ulong> b5 = entry.EB.L5;
		Vector256<ulong> s5 = Swap(b5);
		Vector256<ulong> t5 = b5 + s5;
		left.L5 = b5 + Vector256.Create(SM2Field29.FourPMiddle) - s5;
		Vector256<ulong> m5 = t5 + (t5 << 1);
		right.L5 = (m5 & Vector256.Create(SM2Field29.Mask)) + (m4 >> SM2Field29.Bits);
		Vector256<ulong> b6 = entry.EB.L6;
		Vector256<ulong> s6 = Swap(b6);
		Vector256<ulong> t6 = b6 + s6;
		left.L6 = b6 + Vector256.Create(SM2Field29.FourPMiddle) - s6;
		Vector256<ulong> m6 = t6 + (t6 << 1);
		right.L6 = (m6 & Vector256.Create(SM2Field29.Mask)) + (m5 >> SM2Field29.Bits);
		Vector256<ulong> b7 = entry.EB.L7;
		Vector256<ulong> s7 = Swap(b7);
		Vector256<ulong> t7 = b7 + s7;
		left.L7 = b7 + Vector256.Create(SM2Field29.FourP7) - s7;
		Vector256<ulong> m7 = t7 + (t7 << 1);
		right.L7 = (m7 & Vector256.Create(SM2Field29.Mask)) + (m6 >> SM2Field29.Bits);
		Vector256<ulong> b8 = entry.EB.L8;
		Vector256<ulong> s8 = Swap(b8);
		Vector256<ulong> t8 = b8 + s8;
		left.L8 = b8 + Vector256.Create(SM2Field29.FourP8) - s8;
		Vector256<ulong> m8 = t8 + (t8 << 1);
		right.L8 = m8 + (m7 >> SM2Field29.Bits);
		SM2Field29x4Avx2.Multiply(in left, in right, out SM2Field29x4Avx2 alpha);
		state.P.L0 = Blend0(Avx2.Permute4x64(entry.EA.L0, 0xD8), alpha.L0);
		state.Q.L0 = Blend3(entry.EB.L0, Broadcast0(alpha.L0));
		state.P.L1 = Blend0(Avx2.Permute4x64(entry.EA.L1, 0xD8), alpha.L1);
		state.Q.L1 = Blend3(entry.EB.L1, Broadcast0(alpha.L1));
		state.P.L2 = Blend0(Avx2.Permute4x64(entry.EA.L2, 0xD8), alpha.L2);
		state.Q.L2 = Blend3(entry.EB.L2, Broadcast0(alpha.L2));
		state.P.L3 = Blend0(Avx2.Permute4x64(entry.EA.L3, 0xD8), alpha.L3);
		state.Q.L3 = Blend3(entry.EB.L3, Broadcast0(alpha.L3));
		state.P.L4 = Blend0(Avx2.Permute4x64(entry.EA.L4, 0xD8), alpha.L4);
		state.Q.L4 = Blend3(entry.EB.L4, Broadcast0(alpha.L4));
		state.P.L5 = Blend0(Avx2.Permute4x64(entry.EA.L5, 0xD8), alpha.L5);
		state.Q.L5 = Blend3(entry.EB.L5, Broadcast0(alpha.L5));
		state.P.L6 = Blend0(Avx2.Permute4x64(entry.EA.L6, 0xD8), alpha.L6);
		state.Q.L6 = Blend3(entry.EB.L6, Broadcast0(alpha.L6));
		state.P.L7 = Blend0(Avx2.Permute4x64(entry.EA.L7, 0xD8), alpha.L7);
		state.Q.L7 = Blend3(entry.EB.L7, Broadcast0(alpha.L7));
		state.P.L8 = Blend0(Avx2.Permute4x64(entry.EA.L8, 0xD8), alpha.L8);
		state.Q.L8 = Blend3(entry.EB.L8, Broadcast0(alpha.L8));
	}


	// 4·point, as DoubleTwice with a count of 1.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void DoubleTwice(ref SM2QuadState state)
	{
		DoubleTwice(ref state, 1);
	}

	// 4^count·point, each 4·point in five rounds, all on the same scratch: E0 = [A, γ, B, H] = [α·α, Y·Y, α·X, Y·Z]; E1 = [C8, G4, D, F] = [X·8γ, δ·4γ, T·4γ, α·A] for T = 3B − 2γ + 8p, which give X′ = A − C8 + 4p and Y′ = D − F + 4p, both folded, Z′ = 2H and δ′ = G4; O0 = [α′, ·, γ′, H′] = [(X′ − δ′ + 4p)·3(X′ + δ′), ·, Y′·Y′, Y′·Z′]; O1 = [B′, A′, C8′, G4′] = [α′·X′, α′·α′, 8γ′·X′, 4γ′·δ′], which give X″ = A′ − C8′ + 4p, folded, and δ″ = G4′; and O2 = [D′, F′, α″, ·] = [T′·4γ′, A′·α′, (X″ − δ″ + 4p)·3(X″ + δ″), ·] for T′ = 3B′ − 2γ′ + 8p, which give Y″ = D′ − F′ + 4p, folded and carried, and Z″ = 2H′. The right of E1, [8γ, 4γ, 4γ, A], of O0, [3(X′ + δ′), X′, Y′, Z′], and of O2, [4γ′, α′, 3(X″ + δ″), 4γ′], and the left of O1, [α′, α′, 8γ′, 4γ′], go in carried, in limbs below 2^29 + 2^4, against T and T′ in limbs below 7·2^29 + 2^8, X − δ + 4p in limbs below 5·2^29 + 2^22 and the folded X′ and Y′. A is below 1.3p, B below 1.2p, C8 below 1.8p, D below 3.2p, F below 1.2p, G4 below 1.25p and H below 1.3p, so the folds take values below 7.2p, those of X below 5.3p, and α′ and α″ are below 2.1p. The point at infinity gives some point, which the masks discard.
	[SkipLocalsInit]
	internal static void DoubleTwice(ref SM2QuadState state, int count)
	{
		Unsafe.SkipInit(out SM2QuadScratch5 scratch);
		ref SM2Field29x4Avx2 left = ref AlignedScratch.Start<SM2QuadScratch5, SM2Field29x4Avx2>(ref scratch);
		ref SM2Field29x4Avx2 right = ref Unsafe.Add(ref left, 1);
		ref SM2Field29x4Avx2 first = ref Unsafe.Add(ref left, 2);
		ref SM2Field29x4Avx2 second = ref Unsafe.Add(ref left, 3);
		ref SM2Field29x4Avx2 third = ref Unsafe.Add(ref left, 4);

		for (int i = 0; i < count; ++i)
		{
			left.L0 = Avx2.Permute4x64(state.P.L0, 0x44);
			left.L1 = Avx2.Permute4x64(state.P.L1, 0x44);
			left.L2 = Avx2.Permute4x64(state.P.L2, 0x44);
			left.L3 = Avx2.Permute4x64(state.P.L3, 0x44);
			left.L4 = Avx2.Permute4x64(state.P.L4, 0x44);
			left.L5 = Avx2.Permute4x64(state.P.L5, 0x44);
			left.L6 = Avx2.Permute4x64(state.P.L6, 0x44);
			left.L7 = Avx2.Permute4x64(state.P.L7, 0x44);
			left.L8 = Avx2.Permute4x64(state.P.L8, 0x44);
			SM2Field29x4Avx2.Multiply(in left, in state.P, out first);
			// The right of E1, [8γ, 4γ, 4γ, A], carried; T takes 2γ from it before.
			Vector256<ulong> a0 = first.L0;
			Vector256<ulong> g0 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a0, 0x15), Vector256.Create(3UL, 2, 2, 0));
			left.L0 = MaskedBlend2(state.Q.L0, a0 + (a0 << 1) + Vector256.Create(2 * SM2Field29.FourP0) - (g0 >> 1));
			right.L0 = g0 & Vector256.Create(SM2Field29.Mask);
			Vector256<ulong> a1 = first.L1;
			Vector256<ulong> g1 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a1, 0x15), Vector256.Create(3UL, 2, 2, 0));
			left.L1 = MaskedBlend2(state.Q.L1, a1 + (a1 << 1) + Vector256.Create(2 * SM2Field29.FourP1) - (g1 >> 1));
			right.L1 = (g1 & Vector256.Create(SM2Field29.Mask)) + (g0 >> SM2Field29.Bits);
			Vector256<ulong> a2 = first.L2;
			Vector256<ulong> g2 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a2, 0x15), Vector256.Create(3UL, 2, 2, 0));
			left.L2 = MaskedBlend2(state.Q.L2, a2 + (a2 << 1) + Vector256.Create(2 * SM2Field29.FourP2) - (g2 >> 1));
			right.L2 = (g2 & Vector256.Create(SM2Field29.Mask)) + (g1 >> SM2Field29.Bits);
			Vector256<ulong> a3 = first.L3;
			Vector256<ulong> g3 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a3, 0x15), Vector256.Create(3UL, 2, 2, 0));
			left.L3 = MaskedBlend2(state.Q.L3, a3 + (a3 << 1) + Vector256.Create(2 * SM2Field29.FourP3) - (g3 >> 1));
			right.L3 = (g3 & Vector256.Create(SM2Field29.Mask)) + (g2 >> SM2Field29.Bits);
			Vector256<ulong> a4 = first.L4;
			Vector256<ulong> g4 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a4, 0x15), Vector256.Create(3UL, 2, 2, 0));
			left.L4 = MaskedBlend2(state.Q.L4, a4 + (a4 << 1) + Vector256.Create(2 * SM2Field29.FourPMiddle) - (g4 >> 1));
			right.L4 = (g4 & Vector256.Create(SM2Field29.Mask)) + (g3 >> SM2Field29.Bits);
			Vector256<ulong> a5 = first.L5;
			Vector256<ulong> g5 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a5, 0x15), Vector256.Create(3UL, 2, 2, 0));
			left.L5 = MaskedBlend2(state.Q.L5, a5 + (a5 << 1) + Vector256.Create(2 * SM2Field29.FourPMiddle) - (g5 >> 1));
			right.L5 = (g5 & Vector256.Create(SM2Field29.Mask)) + (g4 >> SM2Field29.Bits);
			Vector256<ulong> a6 = first.L6;
			Vector256<ulong> g6 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a6, 0x15), Vector256.Create(3UL, 2, 2, 0));
			left.L6 = MaskedBlend2(state.Q.L6, a6 + (a6 << 1) + Vector256.Create(2 * SM2Field29.FourPMiddle) - (g6 >> 1));
			right.L6 = (g6 & Vector256.Create(SM2Field29.Mask)) + (g5 >> SM2Field29.Bits);
			Vector256<ulong> a7 = first.L7;
			Vector256<ulong> g7 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a7, 0x15), Vector256.Create(3UL, 2, 2, 0));
			left.L7 = MaskedBlend2(state.Q.L7, a7 + (a7 << 1) + Vector256.Create(2 * SM2Field29.FourP7) - (g7 >> 1));
			right.L7 = (g7 & Vector256.Create(SM2Field29.Mask)) + (g6 >> SM2Field29.Bits);
			Vector256<ulong> a8 = first.L8;
			Vector256<ulong> g8 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a8, 0x15), Vector256.Create(3UL, 2, 2, 0));
			left.L8 = MaskedBlend2(state.Q.L8, a8 + (a8 << 1) + Vector256.Create(2 * SM2Field29.FourP8) - (g8 >> 1));
			right.L8 = g8 + (g7 >> SM2Field29.Bits);
			SM2Field29x4Avx2.Multiply(in left, in right, out second);
			// X′ and Y′ folded, and the right of O0, [3(X′ + δ′), X′, Y′, Z′], carried.
			Vector256<ulong> s8 = Swap(second.L8);
			Vector256<ulong> v8 = MaskedBlend23(first.L8, second.L8) + Vector256.Create(SM2Field29.FourP8) - MaskedBlend23(second.L8, s8);
			Vector256<ulong> h = v8 >> 24;
			v8 &= Vector256.Create(SM2Field29.TopMask);
			Vector256<ulong> s0 = Swap(second.L0);
			Vector256<ulong> v0 = MaskedBlend23(first.L0, second.L0) + Vector256.Create(SM2Field29.FourP0) - MaskedBlend23(second.L0, s0) + h;
			Vector256<ulong> w0 = Avx2.UnpackLow(v0, v0);
			Vector256<ulong> t0 = w0 + s0;
			left.L0 = MaskedBlend0(w0, w0 + Vector256.Create(SM2Field29.FourP0) - s0);
			Vector256<ulong> m0 = MaskedBlend3(MaskedBlend0(w0, t0 + (t0 << 1)), first.L0 << 1);
			right.L0 = m0 & Vector256.Create(SM2Field29.Mask);
			Vector256<ulong> s1 = Swap(second.L1);
			Vector256<ulong> v1 = MaskedBlend23(first.L1, second.L1) + Vector256.Create(SM2Field29.FourP1) - MaskedBlend23(second.L1, s1);
			Vector256<ulong> w1 = Avx2.UnpackLow(v1, v1);
			Vector256<ulong> t1 = w1 + s1;
			left.L1 = MaskedBlend0(w1, w1 + Vector256.Create(SM2Field29.FourP1) - s1);
			Vector256<ulong> m1 = MaskedBlend3(MaskedBlend0(w1, t1 + (t1 << 1)), first.L1 << 1);
			right.L1 = (m1 & Vector256.Create(SM2Field29.Mask)) + (m0 >> SM2Field29.Bits);
			Vector256<ulong> s2 = Swap(second.L2);
			Vector256<ulong> v2 = MaskedBlend23(first.L2, second.L2) + Vector256.Create(SM2Field29.FourPFold2) - MaskedBlend23(second.L2, s2) - (h << 6);
			Vector256<ulong> w2 = Avx2.UnpackLow(v2, v2);
			Vector256<ulong> t2 = w2 + s2;
			left.L2 = MaskedBlend0(w2, w2 + Vector256.Create(SM2Field29.FourP2) - s2);
			Vector256<ulong> m2 = MaskedBlend3(MaskedBlend0(w2, t2 + (t2 << 1)), first.L2 << 1);
			right.L2 = (m2 & Vector256.Create(SM2Field29.Mask)) + (m1 >> SM2Field29.Bits);
			Vector256<ulong> s3 = Swap(second.L3);
			Vector256<ulong> v3 = MaskedBlend23(first.L3, second.L3) + Vector256.Create(SM2Field29.FourPFold3) - MaskedBlend23(second.L3, s3) + (h << 9);
			Vector256<ulong> w3 = Avx2.UnpackLow(v3, v3);
			Vector256<ulong> t3 = w3 + s3;
			left.L3 = MaskedBlend0(w3, w3 + Vector256.Create(SM2Field29.FourP3) - s3);
			Vector256<ulong> m3 = MaskedBlend3(MaskedBlend0(w3, t3 + (t3 << 1)), first.L3 << 1);
			right.L3 = (m3 & Vector256.Create(SM2Field29.Mask)) + (m2 >> SM2Field29.Bits);
			Vector256<ulong> s4 = Swap(second.L4);
			Vector256<ulong> v4 = MaskedBlend23(first.L4, second.L4) + Vector256.Create(SM2Field29.FourPMiddle) - MaskedBlend23(second.L4, s4);
			Vector256<ulong> w4 = Avx2.UnpackLow(v4, v4);
			Vector256<ulong> t4 = w4 + s4;
			left.L4 = MaskedBlend0(w4, w4 + Vector256.Create(SM2Field29.FourPMiddle) - s4);
			Vector256<ulong> m4 = MaskedBlend3(MaskedBlend0(w4, t4 + (t4 << 1)), first.L4 << 1);
			right.L4 = (m4 & Vector256.Create(SM2Field29.Mask)) + (m3 >> SM2Field29.Bits);
			Vector256<ulong> s5 = Swap(second.L5);
			Vector256<ulong> v5 = MaskedBlend23(first.L5, second.L5) + Vector256.Create(SM2Field29.FourPMiddle) - MaskedBlend23(second.L5, s5);
			Vector256<ulong> w5 = Avx2.UnpackLow(v5, v5);
			Vector256<ulong> t5 = w5 + s5;
			left.L5 = MaskedBlend0(w5, w5 + Vector256.Create(SM2Field29.FourPMiddle) - s5);
			Vector256<ulong> m5 = MaskedBlend3(MaskedBlend0(w5, t5 + (t5 << 1)), first.L5 << 1);
			right.L5 = (m5 & Vector256.Create(SM2Field29.Mask)) + (m4 >> SM2Field29.Bits);
			Vector256<ulong> s6 = Swap(second.L6);
			Vector256<ulong> v6 = MaskedBlend23(first.L6, second.L6) + Vector256.Create(SM2Field29.FourPMiddle) - MaskedBlend23(second.L6, s6);
			Vector256<ulong> w6 = Avx2.UnpackLow(v6, v6);
			Vector256<ulong> t6 = w6 + s6;
			left.L6 = MaskedBlend0(w6, w6 + Vector256.Create(SM2Field29.FourPMiddle) - s6);
			Vector256<ulong> m6 = MaskedBlend3(MaskedBlend0(w6, t6 + (t6 << 1)), first.L6 << 1);
			right.L6 = (m6 & Vector256.Create(SM2Field29.Mask)) + (m5 >> SM2Field29.Bits);
			Vector256<ulong> s7 = Swap(second.L7);
			Vector256<ulong> v7 = MaskedBlend23(first.L7, second.L7) + Vector256.Create(SM2Field29.FourP7) - MaskedBlend23(second.L7, s7) + (h << 21);
			Vector256<ulong> w7 = Avx2.UnpackLow(v7, v7);
			Vector256<ulong> t7 = w7 + s7;
			left.L7 = MaskedBlend0(w7, w7 + Vector256.Create(SM2Field29.FourP7) - s7);
			Vector256<ulong> m7 = MaskedBlend3(MaskedBlend0(w7, t7 + (t7 << 1)), first.L7 << 1);
			right.L7 = (m7 & Vector256.Create(SM2Field29.Mask)) + (m6 >> SM2Field29.Bits);
			Vector256<ulong> w8 = Avx2.UnpackLow(v8, v8);
			Vector256<ulong> t8 = w8 + s8;
			left.L8 = MaskedBlend0(w8, w8 + Vector256.Create(SM2Field29.FourP8) - s8);
			Vector256<ulong> m8 = MaskedBlend3(MaskedBlend0(w8, t8 + (t8 << 1)), first.L8 << 1);
			right.L8 = m8 + (m7 >> SM2Field29.Bits);
			SM2Field29x4Avx2.Multiply(in left, in right, out third);
			// gamma and fifth take the buffer of first, fourth that of second and carried that of left, each once no later step reads what it held, so that the frame stays under a page. gamma holds [α′, α′, 8γ′, 4γ′] as O2 takes it, and carried the same carried for O1. The right of O1, [X′, α′, X′, δ′], takes X′ from lane 1 of the left of O0 and δ′ from lane 1 of second.
			ref SM2Field29x4Avx2 gamma = ref first;
			ref SM2Field29x4Avx2 carried = ref left;
			Vector256<ulong> d0 = Avx2.UnpackLow(third.L0, third.L0);
			Vector256<ulong> e0 = Avx2.ShiftLeftLogicalVariable(d0, Vector256.Create(0UL, 0, 3, 2));
			gamma.L0 = e0;
			right.L0 = MaskedBlend1(Avx2.Permute4x64(Avx2.UnpackHigh(left.L0, second.L0), 0x40), d0);
			carried.L0 = e0 & Vector256.Create(SM2Field29.Mask);
			Vector256<ulong> d1 = Avx2.UnpackLow(third.L1, third.L1);
			Vector256<ulong> e1 = Avx2.ShiftLeftLogicalVariable(d1, Vector256.Create(0UL, 0, 3, 2));
			gamma.L1 = e1;
			right.L1 = MaskedBlend1(Avx2.Permute4x64(Avx2.UnpackHigh(left.L1, second.L1), 0x40), d1);
			carried.L1 = (e1 & Vector256.Create(SM2Field29.Mask)) + (e0 >> SM2Field29.Bits);
			Vector256<ulong> d2 = Avx2.UnpackLow(third.L2, third.L2);
			Vector256<ulong> e2 = Avx2.ShiftLeftLogicalVariable(d2, Vector256.Create(0UL, 0, 3, 2));
			gamma.L2 = e2;
			right.L2 = MaskedBlend1(Avx2.Permute4x64(Avx2.UnpackHigh(left.L2, second.L2), 0x40), d2);
			carried.L2 = (e2 & Vector256.Create(SM2Field29.Mask)) + (e1 >> SM2Field29.Bits);
			Vector256<ulong> d3 = Avx2.UnpackLow(third.L3, third.L3);
			Vector256<ulong> e3 = Avx2.ShiftLeftLogicalVariable(d3, Vector256.Create(0UL, 0, 3, 2));
			gamma.L3 = e3;
			right.L3 = MaskedBlend1(Avx2.Permute4x64(Avx2.UnpackHigh(left.L3, second.L3), 0x40), d3);
			carried.L3 = (e3 & Vector256.Create(SM2Field29.Mask)) + (e2 >> SM2Field29.Bits);
			Vector256<ulong> d4 = Avx2.UnpackLow(third.L4, third.L4);
			Vector256<ulong> e4 = Avx2.ShiftLeftLogicalVariable(d4, Vector256.Create(0UL, 0, 3, 2));
			gamma.L4 = e4;
			right.L4 = MaskedBlend1(Avx2.Permute4x64(Avx2.UnpackHigh(left.L4, second.L4), 0x40), d4);
			carried.L4 = (e4 & Vector256.Create(SM2Field29.Mask)) + (e3 >> SM2Field29.Bits);
			Vector256<ulong> d5 = Avx2.UnpackLow(third.L5, third.L5);
			Vector256<ulong> e5 = Avx2.ShiftLeftLogicalVariable(d5, Vector256.Create(0UL, 0, 3, 2));
			gamma.L5 = e5;
			right.L5 = MaskedBlend1(Avx2.Permute4x64(Avx2.UnpackHigh(left.L5, second.L5), 0x40), d5);
			carried.L5 = (e5 & Vector256.Create(SM2Field29.Mask)) + (e4 >> SM2Field29.Bits);
			Vector256<ulong> d6 = Avx2.UnpackLow(third.L6, third.L6);
			Vector256<ulong> e6 = Avx2.ShiftLeftLogicalVariable(d6, Vector256.Create(0UL, 0, 3, 2));
			gamma.L6 = e6;
			right.L6 = MaskedBlend1(Avx2.Permute4x64(Avx2.UnpackHigh(left.L6, second.L6), 0x40), d6);
			carried.L6 = (e6 & Vector256.Create(SM2Field29.Mask)) + (e5 >> SM2Field29.Bits);
			Vector256<ulong> d7 = Avx2.UnpackLow(third.L7, third.L7);
			Vector256<ulong> e7 = Avx2.ShiftLeftLogicalVariable(d7, Vector256.Create(0UL, 0, 3, 2));
			gamma.L7 = e7;
			right.L7 = MaskedBlend1(Avx2.Permute4x64(Avx2.UnpackHigh(left.L7, second.L7), 0x40), d7);
			carried.L7 = (e7 & Vector256.Create(SM2Field29.Mask)) + (e6 >> SM2Field29.Bits);
			Vector256<ulong> d8 = Avx2.UnpackLow(third.L8, third.L8);
			Vector256<ulong> e8 = Avx2.ShiftLeftLogicalVariable(d8, Vector256.Create(0UL, 0, 3, 2));
			gamma.L8 = e8;
			right.L8 = MaskedBlend1(Avx2.Permute4x64(Avx2.UnpackHigh(left.L8, second.L8), 0x40), d8);
			carried.L8 = e8 + (e7 >> SM2Field29.Bits);
			ref SM2Field29x4Avx2 fourth = ref second;
			SM2Field29x4Avx2.Multiply(in carried, in right, out fourth);
			// X″ folded, and the right of O2, [4γ′, α′, 3(X″ + δ″), 4γ′], carried.
			Vector256<ulong> b8 = fourth.L8;
			Vector256<ulong> x8 = Avx2.Permute4x64(b8, 0xD4) + Vector256.Create(SM2Field29.FourP8) - b8;
			Vector256<ulong> k = x8 >> 24;
			x8 &= Vector256.Create(SM2Field29.TopMask);
			Vector256<ulong> b0 = fourth.L0;
			Vector256<ulong> x0 = Avx2.Permute4x64(b0, 0xD4) + Vector256.Create(SM2Field29.FourP0) - b0 + k;
			Vector256<ulong> r0 = Avx2.Permute4x64(gamma.L0, 0xE7);
			Vector256<ulong> n0 = Swap(b0);
			Vector256<ulong> q0 = x0 + n0;
			// The state, whose point no later round reads, takes [X″, δ″, X″, δ″] in Q, whose lane 3 takes α″ after O2.
			state.Q.L0 = Avx2.Permute4x64(MaskedBlend3(x0, b0), 0xEE);
			Vector256<ulong> o0 = MaskedBlend2(r0, q0 + (q0 << 1));
			right.L0 = o0 & Vector256.Create(SM2Field29.Mask);
			left.L0 = MaskedBlend2(MaskedBlend1(b0 + (b0 << 1) + Vector256.Create(2 * SM2Field29.FourP0) - (r0 >> 1), b0), x0 + Vector256.Create(SM2Field29.FourP0) - n0);
			Vector256<ulong> b1 = fourth.L1;
			Vector256<ulong> x1 = Avx2.Permute4x64(b1, 0xD4) + Vector256.Create(SM2Field29.FourP1) - b1;
			Vector256<ulong> r1 = Avx2.Permute4x64(gamma.L1, 0xE7);
			Vector256<ulong> n1 = Swap(b1);
			Vector256<ulong> q1 = x1 + n1;
			state.Q.L1 = Avx2.Permute4x64(MaskedBlend3(x1, b1), 0xEE);
			Vector256<ulong> o1 = MaskedBlend2(r1, q1 + (q1 << 1));
			right.L1 = (o1 & Vector256.Create(SM2Field29.Mask)) + (o0 >> SM2Field29.Bits);
			left.L1 = MaskedBlend2(MaskedBlend1(b1 + (b1 << 1) + Vector256.Create(2 * SM2Field29.FourP1) - (r1 >> 1), b1), x1 + Vector256.Create(SM2Field29.FourP1) - n1);
			Vector256<ulong> b2 = fourth.L2;
			Vector256<ulong> x2 = Avx2.Permute4x64(b2, 0xD4) + Vector256.Create(SM2Field29.FourPFold2) - b2 - (k << 6);
			Vector256<ulong> r2 = Avx2.Permute4x64(gamma.L2, 0xE7);
			Vector256<ulong> n2 = Swap(b2);
			Vector256<ulong> q2 = x2 + n2;
			state.Q.L2 = Avx2.Permute4x64(MaskedBlend3(x2, b2), 0xEE);
			Vector256<ulong> o2 = MaskedBlend2(r2, q2 + (q2 << 1));
			right.L2 = (o2 & Vector256.Create(SM2Field29.Mask)) + (o1 >> SM2Field29.Bits);
			left.L2 = MaskedBlend2(MaskedBlend1(b2 + (b2 << 1) + Vector256.Create(2 * SM2Field29.FourP2) - (r2 >> 1), b2), x2 + Vector256.Create(SM2Field29.FourP2) - n2);
			Vector256<ulong> b3 = fourth.L3;
			Vector256<ulong> x3 = Avx2.Permute4x64(b3, 0xD4) + Vector256.Create(SM2Field29.FourPFold3) - b3 + (k << 9);
			Vector256<ulong> r3 = Avx2.Permute4x64(gamma.L3, 0xE7);
			Vector256<ulong> n3 = Swap(b3);
			Vector256<ulong> q3 = x3 + n3;
			state.Q.L3 = Avx2.Permute4x64(MaskedBlend3(x3, b3), 0xEE);
			Vector256<ulong> o3 = MaskedBlend2(r3, q3 + (q3 << 1));
			right.L3 = (o3 & Vector256.Create(SM2Field29.Mask)) + (o2 >> SM2Field29.Bits);
			left.L3 = MaskedBlend2(MaskedBlend1(b3 + (b3 << 1) + Vector256.Create(2 * SM2Field29.FourP3) - (r3 >> 1), b3), x3 + Vector256.Create(SM2Field29.FourP3) - n3);
			Vector256<ulong> b4 = fourth.L4;
			Vector256<ulong> x4 = Avx2.Permute4x64(b4, 0xD4) + Vector256.Create(SM2Field29.FourPMiddle) - b4;
			Vector256<ulong> r4 = Avx2.Permute4x64(gamma.L4, 0xE7);
			Vector256<ulong> n4 = Swap(b4);
			Vector256<ulong> q4 = x4 + n4;
			state.Q.L4 = Avx2.Permute4x64(MaskedBlend3(x4, b4), 0xEE);
			Vector256<ulong> o4 = MaskedBlend2(r4, q4 + (q4 << 1));
			right.L4 = (o4 & Vector256.Create(SM2Field29.Mask)) + (o3 >> SM2Field29.Bits);
			left.L4 = MaskedBlend2(MaskedBlend1(b4 + (b4 << 1) + Vector256.Create(2 * SM2Field29.FourPMiddle) - (r4 >> 1), b4), x4 + Vector256.Create(SM2Field29.FourPMiddle) - n4);
			Vector256<ulong> b5 = fourth.L5;
			Vector256<ulong> x5 = Avx2.Permute4x64(b5, 0xD4) + Vector256.Create(SM2Field29.FourPMiddle) - b5;
			Vector256<ulong> r5 = Avx2.Permute4x64(gamma.L5, 0xE7);
			Vector256<ulong> n5 = Swap(b5);
			Vector256<ulong> q5 = x5 + n5;
			state.Q.L5 = Avx2.Permute4x64(MaskedBlend3(x5, b5), 0xEE);
			Vector256<ulong> o5 = MaskedBlend2(r5, q5 + (q5 << 1));
			right.L5 = (o5 & Vector256.Create(SM2Field29.Mask)) + (o4 >> SM2Field29.Bits);
			left.L5 = MaskedBlend2(MaskedBlend1(b5 + (b5 << 1) + Vector256.Create(2 * SM2Field29.FourPMiddle) - (r5 >> 1), b5), x5 + Vector256.Create(SM2Field29.FourPMiddle) - n5);
			Vector256<ulong> b6 = fourth.L6;
			Vector256<ulong> x6 = Avx2.Permute4x64(b6, 0xD4) + Vector256.Create(SM2Field29.FourPMiddle) - b6;
			Vector256<ulong> r6 = Avx2.Permute4x64(gamma.L6, 0xE7);
			Vector256<ulong> n6 = Swap(b6);
			Vector256<ulong> q6 = x6 + n6;
			state.Q.L6 = Avx2.Permute4x64(MaskedBlend3(x6, b6), 0xEE);
			Vector256<ulong> o6 = MaskedBlend2(r6, q6 + (q6 << 1));
			right.L6 = (o6 & Vector256.Create(SM2Field29.Mask)) + (o5 >> SM2Field29.Bits);
			left.L6 = MaskedBlend2(MaskedBlend1(b6 + (b6 << 1) + Vector256.Create(2 * SM2Field29.FourPMiddle) - (r6 >> 1), b6), x6 + Vector256.Create(SM2Field29.FourPMiddle) - n6);
			Vector256<ulong> b7 = fourth.L7;
			Vector256<ulong> x7 = Avx2.Permute4x64(b7, 0xD4) + Vector256.Create(SM2Field29.FourP7) - b7 + (k << 21);
			Vector256<ulong> r7 = Avx2.Permute4x64(gamma.L7, 0xE7);
			Vector256<ulong> n7 = Swap(b7);
			Vector256<ulong> q7 = x7 + n7;
			state.Q.L7 = Avx2.Permute4x64(MaskedBlend3(x7, b7), 0xEE);
			Vector256<ulong> o7 = MaskedBlend2(r7, q7 + (q7 << 1));
			right.L7 = (o7 & Vector256.Create(SM2Field29.Mask)) + (o6 >> SM2Field29.Bits);
			left.L7 = MaskedBlend2(MaskedBlend1(b7 + (b7 << 1) + Vector256.Create(2 * SM2Field29.FourP7) - (r7 >> 1), b7), x7 + Vector256.Create(SM2Field29.FourP7) - n7);
			Vector256<ulong> r8 = Avx2.Permute4x64(gamma.L8, 0xE7);
			Vector256<ulong> n8 = Swap(b8);
			Vector256<ulong> q8 = x8 + n8;
			state.Q.L8 = Avx2.Permute4x64(MaskedBlend3(x8, b8), 0xEE);
			Vector256<ulong> o8 = MaskedBlend2(r8, q8 + (q8 << 1));
			right.L8 = o8 + (o7 >> SM2Field29.Bits);
			left.L8 = MaskedBlend2(MaskedBlend1(b8 + (b8 << 1) + Vector256.Create(2 * SM2Field29.FourP8) - (r8 >> 1), b8), x8 + Vector256.Create(SM2Field29.FourP8) - n8);
			ref SM2Field29x4Avx2 fifth = ref first;
			SM2Field29x4Avx2.Multiply(in left, in right, out fifth);
			// Y″ folded and carried.
			Vector256<ulong> c8 = fifth.L8;
			Vector256<ulong> f8 = Swap(c8);
			Vector256<ulong> y8 = c8 + Vector256.Create(SM2Field29.FourP8) - f8;
			Vector256<ulong> j = y8 >> 24;
			y8 &= Vector256.Create(SM2Field29.TopMask);
			Vector256<ulong> c0 = fifth.L0;
			Vector256<ulong> f0 = Swap(c0);
			Vector256<ulong> y0 = c0 + Vector256.Create(SM2Field29.FourP0) - f0 + j;
			Vector256<ulong> z0 = state.Q.L0;
			state.P.L0 = MaskedBlend3(MaskedBlend2(Avx2.Permute4x64(MaskedBlend2(y0 & Vector256.Create(SM2Field29.Mask), c0), 0xE2), z0), third.L0 << 1);
			state.Q.L0 = MaskedBlend3(z0, f0);
			Vector256<ulong> c1 = fifth.L1;
			Vector256<ulong> f1 = Swap(c1);
			Vector256<ulong> y1 = c1 + Vector256.Create(SM2Field29.FourP1) - f1;
			Vector256<ulong> z1 = state.Q.L1;
			state.P.L1 = MaskedBlend3(MaskedBlend2(Avx2.Permute4x64(MaskedBlend2((y1 & Vector256.Create(SM2Field29.Mask)) + (y0 >> SM2Field29.Bits), c1), 0xE2), z1), third.L1 << 1);
			state.Q.L1 = MaskedBlend3(z1, f1);
			Vector256<ulong> c2 = fifth.L2;
			Vector256<ulong> f2 = Swap(c2);
			Vector256<ulong> y2 = c2 + Vector256.Create(SM2Field29.FourPFold2) - f2 - (j << 6);
			Vector256<ulong> z2 = state.Q.L2;
			state.P.L2 = MaskedBlend3(MaskedBlend2(Avx2.Permute4x64(MaskedBlend2((y2 & Vector256.Create(SM2Field29.Mask)) + (y1 >> SM2Field29.Bits), c2), 0xE2), z2), third.L2 << 1);
			state.Q.L2 = MaskedBlend3(z2, f2);
			Vector256<ulong> c3 = fifth.L3;
			Vector256<ulong> f3 = Swap(c3);
			Vector256<ulong> y3 = c3 + Vector256.Create(SM2Field29.FourPFold3) - f3 + (j << 9);
			Vector256<ulong> z3 = state.Q.L3;
			state.P.L3 = MaskedBlend3(MaskedBlend2(Avx2.Permute4x64(MaskedBlend2((y3 & Vector256.Create(SM2Field29.Mask)) + (y2 >> SM2Field29.Bits), c3), 0xE2), z3), third.L3 << 1);
			state.Q.L3 = MaskedBlend3(z3, f3);
			Vector256<ulong> c4 = fifth.L4;
			Vector256<ulong> f4 = Swap(c4);
			Vector256<ulong> y4 = c4 + Vector256.Create(SM2Field29.FourPMiddle) - f4;
			Vector256<ulong> z4 = state.Q.L4;
			state.P.L4 = MaskedBlend3(MaskedBlend2(Avx2.Permute4x64(MaskedBlend2((y4 & Vector256.Create(SM2Field29.Mask)) + (y3 >> SM2Field29.Bits), c4), 0xE2), z4), third.L4 << 1);
			state.Q.L4 = MaskedBlend3(z4, f4);
			Vector256<ulong> c5 = fifth.L5;
			Vector256<ulong> f5 = Swap(c5);
			Vector256<ulong> y5 = c5 + Vector256.Create(SM2Field29.FourPMiddle) - f5;
			Vector256<ulong> z5 = state.Q.L5;
			state.P.L5 = MaskedBlend3(MaskedBlend2(Avx2.Permute4x64(MaskedBlend2((y5 & Vector256.Create(SM2Field29.Mask)) + (y4 >> SM2Field29.Bits), c5), 0xE2), z5), third.L5 << 1);
			state.Q.L5 = MaskedBlend3(z5, f5);
			Vector256<ulong> c6 = fifth.L6;
			Vector256<ulong> f6 = Swap(c6);
			Vector256<ulong> y6 = c6 + Vector256.Create(SM2Field29.FourPMiddle) - f6;
			Vector256<ulong> z6 = state.Q.L6;
			state.P.L6 = MaskedBlend3(MaskedBlend2(Avx2.Permute4x64(MaskedBlend2((y6 & Vector256.Create(SM2Field29.Mask)) + (y5 >> SM2Field29.Bits), c6), 0xE2), z6), third.L6 << 1);
			state.Q.L6 = MaskedBlend3(z6, f6);
			Vector256<ulong> c7 = fifth.L7;
			Vector256<ulong> f7 = Swap(c7);
			Vector256<ulong> y7 = c7 + Vector256.Create(SM2Field29.FourP7) - f7 + (j << 21);
			Vector256<ulong> z7 = state.Q.L7;
			state.P.L7 = MaskedBlend3(MaskedBlend2(Avx2.Permute4x64(MaskedBlend2((y7 & Vector256.Create(SM2Field29.Mask)) + (y6 >> SM2Field29.Bits), c7), 0xE2), z7), third.L7 << 1);
			state.Q.L7 = MaskedBlend3(z7, f7);
			Vector256<ulong> z8 = state.Q.L8;
			state.P.L8 = MaskedBlend3(MaskedBlend2(Avx2.Permute4x64(MaskedBlend2(y8 + (y7 >> SM2Field29.Bits), c8), 0xE2), z8), third.L8 << 1);
			state.Q.L8 = MaskedBlend3(z8, f8);
		}
	}


	// 2·point + entry in six rounds, by the doubling of DoubleTwice and the formulas of ECFormulas.AddDistinct without the factors 2 and 4 of R, I and Z3, for an entry neither equal nor opposite to the double, and neither of them the point at infinity: such lanes give some point, which the masks discard. After E0 and E1: A0 = [U1, U2, K, L] = [X1·Z2², δ1·X2, Z1·Y2, Z1·Z2]; A1 = [Z3, HH, S2, S1] = [L·H, H·H, K·δ1, Y1·Z2³] for H = U2 − U1 + 4p; A2 = [V, H3, RR, d3] = [U1·HH, H·HH, R·R, Z3·Z3] for R = S2 − S1 + 4p, which give X3 = RR − H3 − 2V + 12p, reduced, and W = V − X3 = 3V + H3 − RR + 4p; and A3 = [α, ·, M1, M2] = [(X − δ + 4p)·3(X + δ), ·, R·W, S1·H3], which gives Y3 = M1 − M2 + 4p, folded. X and δ are those of the entry where zeroMask is clear and infinityMask set, of the double where zeroMask is set and of the sum otherwise, and so are Y and Z, which go to the state carried. The right of A1, [H, H, δ1, Z2³], and of A3, [3(X + δ), ·, W, H3], and R in lane 2 of both operands of A2 go in carried, in limbs below 2^29 + 2^4: H and R have limbs below 3·2^29 + 2^6, W limbs below 6·2^29 + 2^8, X3 + 12p limbs below 7·2^29 + 2^6 and X − δ + 4p limbs below 5·2^29 + 2^22. The products of A0 and S1 and S2 are below 1.4p, so H and R are below 5.1p; HH and RR are below 1.9p, H3 below 1.3p and V below 1.1p, so W is below 8.5p, M1 below 2.4p and the fold takes a value below 6.4p, and α is below 2.9p.
	[SkipLocalsInit]
	internal static void DoubleAdd(ref SM2QuadState state, in SM2QuadEntry entry, ref readonly ulong zeroMask, ref readonly ulong infinityMask)
	{
		Unsafe.SkipInit(out SM2Field29x4Avx2 left);
		Unsafe.SkipInit(out SM2Field29x4Avx2 right);
		Unsafe.SkipInit(out SM2Field29x4Avx2 next);
		left.L0 = Avx2.Permute4x64(state.P.L0, 0x44);
		left.L1 = Avx2.Permute4x64(state.P.L1, 0x44);
		left.L2 = Avx2.Permute4x64(state.P.L2, 0x44);
		left.L3 = Avx2.Permute4x64(state.P.L3, 0x44);
		left.L4 = Avx2.Permute4x64(state.P.L4, 0x44);
		left.L5 = Avx2.Permute4x64(state.P.L5, 0x44);
		left.L6 = Avx2.Permute4x64(state.P.L6, 0x44);
		left.L7 = Avx2.Permute4x64(state.P.L7, 0x44);
		left.L8 = Avx2.Permute4x64(state.P.L8, 0x44);
		SM2Field29x4Avx2.Multiply(in left, in state.P, out SM2Field29x4Avx2 first);
		Vector256<ulong> a0 = first.L0;
		Vector256<ulong> g0 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a0, 0x15), Vector256.Create(3UL, 2, 2, 0));
		left.L0 = Blend2(state.Q.L0, a0 + (a0 << 1) + Vector256.Create(2 * SM2Field29.FourP0) - (g0 >> 1));
		right.L0 = g0 & Vector256.Create(SM2Field29.Mask);
		Vector256<ulong> a1 = first.L1;
		Vector256<ulong> g1 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a1, 0x15), Vector256.Create(3UL, 2, 2, 0));
		left.L1 = Blend2(state.Q.L1, a1 + (a1 << 1) + Vector256.Create(2 * SM2Field29.FourP1) - (g1 >> 1));
		right.L1 = (g1 & Vector256.Create(SM2Field29.Mask)) + (g0 >> SM2Field29.Bits);
		Vector256<ulong> a2 = first.L2;
		Vector256<ulong> g2 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a2, 0x15), Vector256.Create(3UL, 2, 2, 0));
		left.L2 = Blend2(state.Q.L2, a2 + (a2 << 1) + Vector256.Create(2 * SM2Field29.FourP2) - (g2 >> 1));
		right.L2 = (g2 & Vector256.Create(SM2Field29.Mask)) + (g1 >> SM2Field29.Bits);
		Vector256<ulong> a3 = first.L3;
		Vector256<ulong> g3 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a3, 0x15), Vector256.Create(3UL, 2, 2, 0));
		left.L3 = Blend2(state.Q.L3, a3 + (a3 << 1) + Vector256.Create(2 * SM2Field29.FourP3) - (g3 >> 1));
		right.L3 = (g3 & Vector256.Create(SM2Field29.Mask)) + (g2 >> SM2Field29.Bits);
		Vector256<ulong> a4 = first.L4;
		Vector256<ulong> g4 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a4, 0x15), Vector256.Create(3UL, 2, 2, 0));
		left.L4 = Blend2(state.Q.L4, a4 + (a4 << 1) + Vector256.Create(2 * SM2Field29.FourPMiddle) - (g4 >> 1));
		right.L4 = (g4 & Vector256.Create(SM2Field29.Mask)) + (g3 >> SM2Field29.Bits);
		Vector256<ulong> a5 = first.L5;
		Vector256<ulong> g5 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a5, 0x15), Vector256.Create(3UL, 2, 2, 0));
		left.L5 = Blend2(state.Q.L5, a5 + (a5 << 1) + Vector256.Create(2 * SM2Field29.FourPMiddle) - (g5 >> 1));
		right.L5 = (g5 & Vector256.Create(SM2Field29.Mask)) + (g4 >> SM2Field29.Bits);
		Vector256<ulong> a6 = first.L6;
		Vector256<ulong> g6 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a6, 0x15), Vector256.Create(3UL, 2, 2, 0));
		left.L6 = Blend2(state.Q.L6, a6 + (a6 << 1) + Vector256.Create(2 * SM2Field29.FourPMiddle) - (g6 >> 1));
		right.L6 = (g6 & Vector256.Create(SM2Field29.Mask)) + (g5 >> SM2Field29.Bits);
		Vector256<ulong> a7 = first.L7;
		Vector256<ulong> g7 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a7, 0x15), Vector256.Create(3UL, 2, 2, 0));
		left.L7 = Blend2(state.Q.L7, a7 + (a7 << 1) + Vector256.Create(2 * SM2Field29.FourP7) - (g7 >> 1));
		right.L7 = (g7 & Vector256.Create(SM2Field29.Mask)) + (g6 >> SM2Field29.Bits);
		Vector256<ulong> a8 = first.L8;
		Vector256<ulong> g8 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a8, 0x15), Vector256.Create(3UL, 2, 2, 0));
		left.L8 = Blend2(state.Q.L8, a8 + (a8 << 1) + Vector256.Create(2 * SM2Field29.FourP8) - (g8 >> 1));
		right.L8 = g8 + (g7 >> SM2Field29.Bits);
		SM2Field29x4Avx2.Multiply(in left, in right, out SM2Field29x4Avx2 second);
		Vector256<ulong> s8 = Swap(second.L8);
		Vector256<ulong> v8 = Blend23(first.L8, second.L8) + Vector256.Create(SM2Field29.FourP8) - Blend23(second.L8, s8);
		Vector256<ulong> h = v8 >> 24;
		v8 &= Vector256.Create(SM2Field29.TopMask);
		Vector256<ulong> s0 = Swap(second.L0);
		Vector256<ulong> v0 = Blend23(first.L0, second.L0) + Vector256.Create(SM2Field29.FourP0) - Blend23(second.L0, s0) + h;
		Vector256<ulong> z0 = first.L0 << 1;
		// The state, whose point no later round reads, takes the double, P = [X′, ·, Y′, Z′] and Q = [X′, δ′, Y′, ·], for the Y′ and δ′ of A1 and for the lanes where zeroMask is set.
		state.P.L0 = Blend3(v0, z0);
		state.Q.L0 = Blend1(v0, second.L0);
		left.L0 = Blend1(Blend23(v0, Avx2.UnpackHigh(z0, z0)), second.L0);
		Vector256<ulong> s1 = Swap(second.L1);
		Vector256<ulong> v1 = Blend23(first.L1, second.L1) + Vector256.Create(SM2Field29.FourP1) - Blend23(second.L1, s1);
		Vector256<ulong> z1 = first.L1 << 1;
		state.P.L1 = Blend3(v1, z1);
		state.Q.L1 = Blend1(v1, second.L1);
		left.L1 = Blend1(Blend23(v1, Avx2.UnpackHigh(z1, z1)), second.L1);
		Vector256<ulong> s2 = Swap(second.L2);
		Vector256<ulong> v2 = Blend23(first.L2, second.L2) + Vector256.Create(SM2Field29.FourPFold2) - Blend23(second.L2, s2) - (h << 6);
		Vector256<ulong> z2 = first.L2 << 1;
		state.P.L2 = Blend3(v2, z2);
		state.Q.L2 = Blend1(v2, second.L2);
		left.L2 = Blend1(Blend23(v2, Avx2.UnpackHigh(z2, z2)), second.L2);
		Vector256<ulong> s3 = Swap(second.L3);
		Vector256<ulong> v3 = Blend23(first.L3, second.L3) + Vector256.Create(SM2Field29.FourPFold3) - Blend23(second.L3, s3) + (h << 9);
		Vector256<ulong> z3 = first.L3 << 1;
		state.P.L3 = Blend3(v3, z3);
		state.Q.L3 = Blend1(v3, second.L3);
		left.L3 = Blend1(Blend23(v3, Avx2.UnpackHigh(z3, z3)), second.L3);
		Vector256<ulong> s4 = Swap(second.L4);
		Vector256<ulong> v4 = Blend23(first.L4, second.L4) + Vector256.Create(SM2Field29.FourPMiddle) - Blend23(second.L4, s4);
		Vector256<ulong> z4 = first.L4 << 1;
		state.P.L4 = Blend3(v4, z4);
		state.Q.L4 = Blend1(v4, second.L4);
		left.L4 = Blend1(Blend23(v4, Avx2.UnpackHigh(z4, z4)), second.L4);
		Vector256<ulong> s5 = Swap(second.L5);
		Vector256<ulong> v5 = Blend23(first.L5, second.L5) + Vector256.Create(SM2Field29.FourPMiddle) - Blend23(second.L5, s5);
		Vector256<ulong> z5 = first.L5 << 1;
		state.P.L5 = Blend3(v5, z5);
		state.Q.L5 = Blend1(v5, second.L5);
		left.L5 = Blend1(Blend23(v5, Avx2.UnpackHigh(z5, z5)), second.L5);
		Vector256<ulong> s6 = Swap(second.L6);
		Vector256<ulong> v6 = Blend23(first.L6, second.L6) + Vector256.Create(SM2Field29.FourPMiddle) - Blend23(second.L6, s6);
		Vector256<ulong> z6 = first.L6 << 1;
		state.P.L6 = Blend3(v6, z6);
		state.Q.L6 = Blend1(v6, second.L6);
		left.L6 = Blend1(Blend23(v6, Avx2.UnpackHigh(z6, z6)), second.L6);
		Vector256<ulong> s7 = Swap(second.L7);
		Vector256<ulong> v7 = Blend23(first.L7, second.L7) + Vector256.Create(SM2Field29.FourP7) - Blend23(second.L7, s7) + (h << 21);
		Vector256<ulong> z7 = first.L7 << 1;
		state.P.L7 = Blend3(v7, z7);
		state.Q.L7 = Blend1(v7, second.L7);
		left.L7 = Blend1(Blend23(v7, Avx2.UnpackHigh(z7, z7)), second.L7);
		Vector256<ulong> z8 = first.L8 << 1;
		state.P.L8 = Blend3(v8, z8);
		state.Q.L8 = Blend1(v8, second.L8);
		left.L8 = Blend1(Blend23(v8, Avx2.UnpackHigh(z8, z8)), second.L8);
		// third, fifth and sixth take the buffer of first, and fourth that of second, each once no later step reads what it held, so that the frame stays under a page.
		ref SM2Field29x4Avx2 third = ref first;
		SM2Field29x4Avx2.Multiply(in left, in entry.EA, out third);
		// The right of A1, [H, H, δ1, Z2³], carried.
		Vector256<ulong> c0 = third.L0;
		Vector256<ulong> d0 = c0 + Vector256.Create(SM2Field29.FourP0) - Swap(c0);
		left.L0 = Blend23(Blend1(Broadcast3(c0), d0), Blend3(c0, Swap(state.P.L0)));
		Vector256<ulong> o0 = Blend3(Blend2(Avx2.UnpackHigh(d0, d0), Broadcast1(state.Q.L0)), entry.EB.L0);
		right.L0 = o0 & Vector256.Create(SM2Field29.Mask);
		Vector256<ulong> c1 = third.L1;
		Vector256<ulong> d1 = c1 + Vector256.Create(SM2Field29.FourP1) - Swap(c1);
		left.L1 = Blend23(Blend1(Broadcast3(c1), d1), Blend3(c1, Swap(state.P.L1)));
		Vector256<ulong> o1 = Blend3(Blend2(Avx2.UnpackHigh(d1, d1), Broadcast1(state.Q.L1)), entry.EB.L1);
		right.L1 = (o1 & Vector256.Create(SM2Field29.Mask)) + (o0 >> SM2Field29.Bits);
		Vector256<ulong> c2 = third.L2;
		Vector256<ulong> d2 = c2 + Vector256.Create(SM2Field29.FourP2) - Swap(c2);
		left.L2 = Blend23(Blend1(Broadcast3(c2), d2), Blend3(c2, Swap(state.P.L2)));
		Vector256<ulong> o2 = Blend3(Blend2(Avx2.UnpackHigh(d2, d2), Broadcast1(state.Q.L2)), entry.EB.L2);
		right.L2 = (o2 & Vector256.Create(SM2Field29.Mask)) + (o1 >> SM2Field29.Bits);
		Vector256<ulong> c3 = third.L3;
		Vector256<ulong> d3 = c3 + Vector256.Create(SM2Field29.FourP3) - Swap(c3);
		left.L3 = Blend23(Blend1(Broadcast3(c3), d3), Blend3(c3, Swap(state.P.L3)));
		Vector256<ulong> o3 = Blend3(Blend2(Avx2.UnpackHigh(d3, d3), Broadcast1(state.Q.L3)), entry.EB.L3);
		right.L3 = (o3 & Vector256.Create(SM2Field29.Mask)) + (o2 >> SM2Field29.Bits);
		Vector256<ulong> c4 = third.L4;
		Vector256<ulong> d4 = c4 + Vector256.Create(SM2Field29.FourPMiddle) - Swap(c4);
		left.L4 = Blend23(Blend1(Broadcast3(c4), d4), Blend3(c4, Swap(state.P.L4)));
		Vector256<ulong> o4 = Blend3(Blend2(Avx2.UnpackHigh(d4, d4), Broadcast1(state.Q.L4)), entry.EB.L4);
		right.L4 = (o4 & Vector256.Create(SM2Field29.Mask)) + (o3 >> SM2Field29.Bits);
		Vector256<ulong> c5 = third.L5;
		Vector256<ulong> d5 = c5 + Vector256.Create(SM2Field29.FourPMiddle) - Swap(c5);
		left.L5 = Blend23(Blend1(Broadcast3(c5), d5), Blend3(c5, Swap(state.P.L5)));
		Vector256<ulong> o5 = Blend3(Blend2(Avx2.UnpackHigh(d5, d5), Broadcast1(state.Q.L5)), entry.EB.L5);
		right.L5 = (o5 & Vector256.Create(SM2Field29.Mask)) + (o4 >> SM2Field29.Bits);
		Vector256<ulong> c6 = third.L6;
		Vector256<ulong> d6 = c6 + Vector256.Create(SM2Field29.FourPMiddle) - Swap(c6);
		left.L6 = Blend23(Blend1(Broadcast3(c6), d6), Blend3(c6, Swap(state.P.L6)));
		Vector256<ulong> o6 = Blend3(Blend2(Avx2.UnpackHigh(d6, d6), Broadcast1(state.Q.L6)), entry.EB.L6);
		right.L6 = (o6 & Vector256.Create(SM2Field29.Mask)) + (o5 >> SM2Field29.Bits);
		Vector256<ulong> c7 = third.L7;
		Vector256<ulong> d7 = c7 + Vector256.Create(SM2Field29.FourP7) - Swap(c7);
		left.L7 = Blend23(Blend1(Broadcast3(c7), d7), Blend3(c7, Swap(state.P.L7)));
		Vector256<ulong> o7 = Blend3(Blend2(Avx2.UnpackHigh(d7, d7), Broadcast1(state.Q.L7)), entry.EB.L7);
		right.L7 = (o7 & Vector256.Create(SM2Field29.Mask)) + (o6 >> SM2Field29.Bits);
		Vector256<ulong> c8 = third.L8;
		Vector256<ulong> d8 = c8 + Vector256.Create(SM2Field29.FourP8) - Swap(c8);
		left.L8 = Blend23(Blend1(Broadcast3(c8), d8), Blend3(c8, Swap(state.P.L8)));
		Vector256<ulong> o8 = Blend3(Blend2(Avx2.UnpackHigh(d8, d8), Broadcast1(state.Q.L8)), entry.EB.L8);
		right.L8 = o8 + (o7 >> SM2Field29.Bits);
		ref SM2Field29x4Avx2 fourth = ref second;
		SM2Field29x4Avx2.Multiply(in left, in right, out fourth);
		// R carried, in the lanes 2 of both operands of A2; H from lane 1 of the right of A1, read before right takes that of A2.
		Vector256<ulong> b0 = fourth.L0;
		Vector256<ulong> r0 = b0 + Vector256.Create(SM2Field29.FourP0) - Swap(b0);
		Vector256<ulong> q0 = Blend3(r0 & Vector256.Create(SM2Field29.Mask), Broadcast0(b0));
		left.L0 = Blend23(Blend1(third.L0, right.L0), q0);
		right.L0 = Blend23(Avx2.UnpackHigh(b0, b0), q0);
		Vector256<ulong> b1 = fourth.L1;
		Vector256<ulong> r1 = b1 + Vector256.Create(SM2Field29.FourP1) - Swap(b1);
		Vector256<ulong> q1 = Blend3((r1 & Vector256.Create(SM2Field29.Mask)) + (r0 >> SM2Field29.Bits), Broadcast0(b1));
		left.L1 = Blend23(Blend1(third.L1, right.L1), q1);
		right.L1 = Blend23(Avx2.UnpackHigh(b1, b1), q1);
		Vector256<ulong> b2 = fourth.L2;
		Vector256<ulong> r2 = b2 + Vector256.Create(SM2Field29.FourP2) - Swap(b2);
		Vector256<ulong> q2 = Blend3((r2 & Vector256.Create(SM2Field29.Mask)) + (r1 >> SM2Field29.Bits), Broadcast0(b2));
		left.L2 = Blend23(Blend1(third.L2, right.L2), q2);
		right.L2 = Blend23(Avx2.UnpackHigh(b2, b2), q2);
		Vector256<ulong> b3 = fourth.L3;
		Vector256<ulong> r3 = b3 + Vector256.Create(SM2Field29.FourP3) - Swap(b3);
		Vector256<ulong> q3 = Blend3((r3 & Vector256.Create(SM2Field29.Mask)) + (r2 >> SM2Field29.Bits), Broadcast0(b3));
		left.L3 = Blend23(Blend1(third.L3, right.L3), q3);
		right.L3 = Blend23(Avx2.UnpackHigh(b3, b3), q3);
		Vector256<ulong> b4 = fourth.L4;
		Vector256<ulong> r4 = b4 + Vector256.Create(SM2Field29.FourPMiddle) - Swap(b4);
		Vector256<ulong> q4 = Blend3((r4 & Vector256.Create(SM2Field29.Mask)) + (r3 >> SM2Field29.Bits), Broadcast0(b4));
		left.L4 = Blend23(Blend1(third.L4, right.L4), q4);
		right.L4 = Blend23(Avx2.UnpackHigh(b4, b4), q4);
		Vector256<ulong> b5 = fourth.L5;
		Vector256<ulong> r5 = b5 + Vector256.Create(SM2Field29.FourPMiddle) - Swap(b5);
		Vector256<ulong> q5 = Blend3((r5 & Vector256.Create(SM2Field29.Mask)) + (r4 >> SM2Field29.Bits), Broadcast0(b5));
		left.L5 = Blend23(Blend1(third.L5, right.L5), q5);
		right.L5 = Blend23(Avx2.UnpackHigh(b5, b5), q5);
		Vector256<ulong> b6 = fourth.L6;
		Vector256<ulong> r6 = b6 + Vector256.Create(SM2Field29.FourPMiddle) - Swap(b6);
		Vector256<ulong> q6 = Blend3((r6 & Vector256.Create(SM2Field29.Mask)) + (r5 >> SM2Field29.Bits), Broadcast0(b6));
		left.L6 = Blend23(Blend1(third.L6, right.L6), q6);
		right.L6 = Blend23(Avx2.UnpackHigh(b6, b6), q6);
		Vector256<ulong> b7 = fourth.L7;
		Vector256<ulong> r7 = b7 + Vector256.Create(SM2Field29.FourP7) - Swap(b7);
		Vector256<ulong> q7 = Blend3((r7 & Vector256.Create(SM2Field29.Mask)) + (r6 >> SM2Field29.Bits), Broadcast0(b7));
		left.L7 = Blend23(Blend1(third.L7, right.L7), q7);
		right.L7 = Blend23(Avx2.UnpackHigh(b7, b7), q7);
		Vector256<ulong> b8 = fourth.L8;
		Vector256<ulong> r8 = b8 + Vector256.Create(SM2Field29.FourP8) - Swap(b8);
		Vector256<ulong> q8 = Blend3(r8 + (r7 >> SM2Field29.Bits), Broadcast0(b8));
		left.L8 = Blend23(Blend1(third.L8, right.L8), q8);
		right.L8 = Blend23(Avx2.UnpackHigh(b8, b8), q8);
		ref SM2Field29x4Avx2 fifth = ref first;
		SM2Field29x4Avx2.Multiply(in left, in right, out fifth);
		Vector256<ulong> e0 = fifth.L0;
		Vector256<ulong> p0 = Broadcast0(e0);
		Vector256<ulong> n0 = Broadcast1(e0);
		next.L0 = e0 + Vector256.Create(3 * SM2Field29.FourP0) - (n0 + (p0 << 1));
		// The right of A3 takes W and H3 here and 3(X + δ) in lane 0 after the selects.
		right.L0 = Blend3((p0 << 1) + p0 + n0 + Vector256.Create(SM2Field29.FourP0) - e0, n0);
		Vector256<ulong> e1 = fifth.L1;
		Vector256<ulong> p1 = Broadcast0(e1);
		Vector256<ulong> n1 = Broadcast1(e1);
		next.L1 = e1 + Vector256.Create(3 * SM2Field29.FourP1) - (n1 + (p1 << 1));
		right.L1 = Blend3((p1 << 1) + p1 + n1 + Vector256.Create(SM2Field29.FourP1) - e1, n1);
		Vector256<ulong> e2 = fifth.L2;
		Vector256<ulong> p2 = Broadcast0(e2);
		Vector256<ulong> n2 = Broadcast1(e2);
		next.L2 = e2 + Vector256.Create(3 * SM2Field29.FourP2) - (n2 + (p2 << 1));
		right.L2 = Blend3((p2 << 1) + p2 + n2 + Vector256.Create(SM2Field29.FourP2) - e2, n2);
		Vector256<ulong> e3 = fifth.L3;
		Vector256<ulong> p3 = Broadcast0(e3);
		Vector256<ulong> n3 = Broadcast1(e3);
		next.L3 = e3 + Vector256.Create(3 * SM2Field29.FourP3) - (n3 + (p3 << 1));
		right.L3 = Blend3((p3 << 1) + p3 + n3 + Vector256.Create(SM2Field29.FourP3) - e3, n3);
		Vector256<ulong> e4 = fifth.L4;
		Vector256<ulong> p4 = Broadcast0(e4);
		Vector256<ulong> n4 = Broadcast1(e4);
		next.L4 = e4 + Vector256.Create(3 * SM2Field29.FourPMiddle) - (n4 + (p4 << 1));
		right.L4 = Blend3((p4 << 1) + p4 + n4 + Vector256.Create(SM2Field29.FourPMiddle) - e4, n4);
		Vector256<ulong> e5 = fifth.L5;
		Vector256<ulong> p5 = Broadcast0(e5);
		Vector256<ulong> n5 = Broadcast1(e5);
		next.L5 = e5 + Vector256.Create(3 * SM2Field29.FourPMiddle) - (n5 + (p5 << 1));
		right.L5 = Blend3((p5 << 1) + p5 + n5 + Vector256.Create(SM2Field29.FourPMiddle) - e5, n5);
		Vector256<ulong> e6 = fifth.L6;
		Vector256<ulong> p6 = Broadcast0(e6);
		Vector256<ulong> n6 = Broadcast1(e6);
		next.L6 = e6 + Vector256.Create(3 * SM2Field29.FourPMiddle) - (n6 + (p6 << 1));
		right.L6 = Blend3((p6 << 1) + p6 + n6 + Vector256.Create(SM2Field29.FourPMiddle) - e6, n6);
		Vector256<ulong> e7 = fifth.L7;
		Vector256<ulong> p7 = Broadcast0(e7);
		Vector256<ulong> n7 = Broadcast1(e7);
		next.L7 = e7 + Vector256.Create(3 * SM2Field29.FourP7) - (n7 + (p7 << 1));
		right.L7 = Blend3((p7 << 1) + p7 + n7 + Vector256.Create(SM2Field29.FourP7) - e7, n7);
		Vector256<ulong> e8 = fifth.L8;
		Vector256<ulong> p8 = Broadcast0(e8);
		Vector256<ulong> n8 = Broadcast1(e8);
		next.L8 = e8 + Vector256.Create(3 * SM2Field29.FourP8) - (n8 + (p8 << 1));
		right.L8 = Blend3((p8 << 1) + p8 + n8 + Vector256.Create(SM2Field29.FourP8) - e8, n8);
		SM2Field29x4Avx2.Reduce(in next, out next);
		Vector256<ulong> zero = Vector256.LoadUnsafe(in zeroMask);
		Vector256<ulong> infinity = Vector256.LoadUnsafe(in infinityMask);
		// The right of A3 carried.
		Vector256<ulong> x0 = Vector256.ConditionalSelect(zero, state.Q.L0, Vector256.ConditionalSelect(infinity, entry.EB.L0, Avx2.Permute4x64(Blend3(next.L0, fifth.L0), 0xEE)));
		Vector256<ulong> m0 = Swap(x0);
		Vector256<ulong> t0 = x0 + m0;
		// Q keeps the X and δ of the result, and R comes from lane 2 of the left of A2.
		state.Q.L0 = x0;
		left.L0 = Blend0(Blend3(left.L0, fourth.L0), x0 + Vector256.Create(SM2Field29.FourP0) - m0);
		Vector256<ulong> w0 = Blend0(right.L0, t0 + (t0 << 1));
		right.L0 = w0 & Vector256.Create(SM2Field29.Mask);
		Vector256<ulong> x1 = Vector256.ConditionalSelect(zero, state.Q.L1, Vector256.ConditionalSelect(infinity, entry.EB.L1, Avx2.Permute4x64(Blend3(next.L1, fifth.L1), 0xEE)));
		Vector256<ulong> m1 = Swap(x1);
		Vector256<ulong> t1 = x1 + m1;
		state.Q.L1 = x1;
		left.L1 = Blend0(Blend3(left.L1, fourth.L1), x1 + Vector256.Create(SM2Field29.FourP1) - m1);
		Vector256<ulong> w1 = Blend0(right.L1, t1 + (t1 << 1));
		right.L1 = (w1 & Vector256.Create(SM2Field29.Mask)) + (w0 >> SM2Field29.Bits);
		Vector256<ulong> x2 = Vector256.ConditionalSelect(zero, state.Q.L2, Vector256.ConditionalSelect(infinity, entry.EB.L2, Avx2.Permute4x64(Blend3(next.L2, fifth.L2), 0xEE)));
		Vector256<ulong> m2 = Swap(x2);
		Vector256<ulong> t2 = x2 + m2;
		state.Q.L2 = x2;
		left.L2 = Blend0(Blend3(left.L2, fourth.L2), x2 + Vector256.Create(SM2Field29.FourP2) - m2);
		Vector256<ulong> w2 = Blend0(right.L2, t2 + (t2 << 1));
		right.L2 = (w2 & Vector256.Create(SM2Field29.Mask)) + (w1 >> SM2Field29.Bits);
		Vector256<ulong> x3 = Vector256.ConditionalSelect(zero, state.Q.L3, Vector256.ConditionalSelect(infinity, entry.EB.L3, Avx2.Permute4x64(Blend3(next.L3, fifth.L3), 0xEE)));
		Vector256<ulong> m3 = Swap(x3);
		Vector256<ulong> t3 = x3 + m3;
		state.Q.L3 = x3;
		left.L3 = Blend0(Blend3(left.L3, fourth.L3), x3 + Vector256.Create(SM2Field29.FourP3) - m3);
		Vector256<ulong> w3 = Blend0(right.L3, t3 + (t3 << 1));
		right.L3 = (w3 & Vector256.Create(SM2Field29.Mask)) + (w2 >> SM2Field29.Bits);
		Vector256<ulong> x4 = Vector256.ConditionalSelect(zero, state.Q.L4, Vector256.ConditionalSelect(infinity, entry.EB.L4, Avx2.Permute4x64(Blend3(next.L4, fifth.L4), 0xEE)));
		Vector256<ulong> m4 = Swap(x4);
		Vector256<ulong> t4 = x4 + m4;
		state.Q.L4 = x4;
		left.L4 = Blend0(Blend3(left.L4, fourth.L4), x4 + Vector256.Create(SM2Field29.FourPMiddle) - m4);
		Vector256<ulong> w4 = Blend0(right.L4, t4 + (t4 << 1));
		right.L4 = (w4 & Vector256.Create(SM2Field29.Mask)) + (w3 >> SM2Field29.Bits);
		Vector256<ulong> x5 = Vector256.ConditionalSelect(zero, state.Q.L5, Vector256.ConditionalSelect(infinity, entry.EB.L5, Avx2.Permute4x64(Blend3(next.L5, fifth.L5), 0xEE)));
		Vector256<ulong> m5 = Swap(x5);
		Vector256<ulong> t5 = x5 + m5;
		state.Q.L5 = x5;
		left.L5 = Blend0(Blend3(left.L5, fourth.L5), x5 + Vector256.Create(SM2Field29.FourPMiddle) - m5);
		Vector256<ulong> w5 = Blend0(right.L5, t5 + (t5 << 1));
		right.L5 = (w5 & Vector256.Create(SM2Field29.Mask)) + (w4 >> SM2Field29.Bits);
		Vector256<ulong> x6 = Vector256.ConditionalSelect(zero, state.Q.L6, Vector256.ConditionalSelect(infinity, entry.EB.L6, Avx2.Permute4x64(Blend3(next.L6, fifth.L6), 0xEE)));
		Vector256<ulong> m6 = Swap(x6);
		Vector256<ulong> t6 = x6 + m6;
		state.Q.L6 = x6;
		left.L6 = Blend0(Blend3(left.L6, fourth.L6), x6 + Vector256.Create(SM2Field29.FourPMiddle) - m6);
		Vector256<ulong> w6 = Blend0(right.L6, t6 + (t6 << 1));
		right.L6 = (w6 & Vector256.Create(SM2Field29.Mask)) + (w5 >> SM2Field29.Bits);
		Vector256<ulong> x7 = Vector256.ConditionalSelect(zero, state.Q.L7, Vector256.ConditionalSelect(infinity, entry.EB.L7, Avx2.Permute4x64(Blend3(next.L7, fifth.L7), 0xEE)));
		Vector256<ulong> m7 = Swap(x7);
		Vector256<ulong> t7 = x7 + m7;
		state.Q.L7 = x7;
		left.L7 = Blend0(Blend3(left.L7, fourth.L7), x7 + Vector256.Create(SM2Field29.FourP7) - m7);
		Vector256<ulong> w7 = Blend0(right.L7, t7 + (t7 << 1));
		right.L7 = (w7 & Vector256.Create(SM2Field29.Mask)) + (w6 >> SM2Field29.Bits);
		Vector256<ulong> x8 = Vector256.ConditionalSelect(zero, state.Q.L8, Vector256.ConditionalSelect(infinity, entry.EB.L8, Avx2.Permute4x64(Blend3(next.L8, fifth.L8), 0xEE)));
		Vector256<ulong> m8 = Swap(x8);
		Vector256<ulong> t8 = x8 + m8;
		state.Q.L8 = x8;
		left.L8 = Blend0(Blend3(left.L8, fourth.L8), x8 + Vector256.Create(SM2Field29.FourP8) - m8);
		Vector256<ulong> w8 = Blend0(right.L8, t8 + (t8 << 1));
		right.L8 = w8 + (w7 >> SM2Field29.Bits);
		ref SM2Field29x4Avx2 sixth = ref first;
		SM2Field29x4Avx2.Multiply(in left, in right, out sixth);
		// Y3 folded, and the Y and Z of the result carried.
		Vector256<ulong> f8 = sixth.L8;
		Vector256<ulong> y8 = f8 + Vector256.Create(SM2Field29.FourP8) - Swap(f8);
		Vector256<ulong> j = y8 >> 24;
		y8 &= Vector256.Create(SM2Field29.TopMask);
		Vector256<ulong> f0 = sixth.L0;
		Vector256<ulong> y0 = f0 + Vector256.Create(SM2Field29.FourP0) - Swap(f0) + j;
		Vector256<ulong> u0 = Vector256.ConditionalSelect(zero, state.P.L0, Vector256.ConditionalSelect(infinity, entry.EA.L0, Blend3(y0, Broadcast0(fourth.L0))));
		Vector256<ulong> k0 = state.Q.L0;
		state.P.L0 = Blend2(Avx2.Permute4x64(Blend0(u0 & Vector256.Create(SM2Field29.Mask), f0), 0xE8), Broadcast0(k0));
		state.Q.L0 = Blend3(k0, Broadcast0(f0));
		Vector256<ulong> f1 = sixth.L1;
		Vector256<ulong> y1 = f1 + Vector256.Create(SM2Field29.FourP1) - Swap(f1);
		Vector256<ulong> u1 = Vector256.ConditionalSelect(zero, state.P.L1, Vector256.ConditionalSelect(infinity, entry.EA.L1, Blend3(y1, Broadcast0(fourth.L1))));
		Vector256<ulong> k1 = state.Q.L1;
		state.P.L1 = Blend2(Avx2.Permute4x64(Blend0((u1 & Vector256.Create(SM2Field29.Mask)) + (u0 >> SM2Field29.Bits), f1), 0xE8), Broadcast0(k1));
		state.Q.L1 = Blend3(k1, Broadcast0(f1));
		Vector256<ulong> f2 = sixth.L2;
		Vector256<ulong> y2 = f2 + Vector256.Create(SM2Field29.FourPFold2) - Swap(f2) - (j << 6);
		Vector256<ulong> u2 = Vector256.ConditionalSelect(zero, state.P.L2, Vector256.ConditionalSelect(infinity, entry.EA.L2, Blend3(y2, Broadcast0(fourth.L2))));
		Vector256<ulong> k2 = state.Q.L2;
		state.P.L2 = Blend2(Avx2.Permute4x64(Blend0((u2 & Vector256.Create(SM2Field29.Mask)) + (u1 >> SM2Field29.Bits), f2), 0xE8), Broadcast0(k2));
		state.Q.L2 = Blend3(k2, Broadcast0(f2));
		Vector256<ulong> f3 = sixth.L3;
		Vector256<ulong> y3 = f3 + Vector256.Create(SM2Field29.FourPFold3) - Swap(f3) + (j << 9);
		Vector256<ulong> u3 = Vector256.ConditionalSelect(zero, state.P.L3, Vector256.ConditionalSelect(infinity, entry.EA.L3, Blend3(y3, Broadcast0(fourth.L3))));
		Vector256<ulong> k3 = state.Q.L3;
		state.P.L3 = Blend2(Avx2.Permute4x64(Blend0((u3 & Vector256.Create(SM2Field29.Mask)) + (u2 >> SM2Field29.Bits), f3), 0xE8), Broadcast0(k3));
		state.Q.L3 = Blend3(k3, Broadcast0(f3));
		Vector256<ulong> f4 = sixth.L4;
		Vector256<ulong> y4 = f4 + Vector256.Create(SM2Field29.FourPMiddle) - Swap(f4);
		Vector256<ulong> u4 = Vector256.ConditionalSelect(zero, state.P.L4, Vector256.ConditionalSelect(infinity, entry.EA.L4, Blend3(y4, Broadcast0(fourth.L4))));
		Vector256<ulong> k4 = state.Q.L4;
		state.P.L4 = Blend2(Avx2.Permute4x64(Blend0((u4 & Vector256.Create(SM2Field29.Mask)) + (u3 >> SM2Field29.Bits), f4), 0xE8), Broadcast0(k4));
		state.Q.L4 = Blend3(k4, Broadcast0(f4));
		Vector256<ulong> f5 = sixth.L5;
		Vector256<ulong> y5 = f5 + Vector256.Create(SM2Field29.FourPMiddle) - Swap(f5);
		Vector256<ulong> u5 = Vector256.ConditionalSelect(zero, state.P.L5, Vector256.ConditionalSelect(infinity, entry.EA.L5, Blend3(y5, Broadcast0(fourth.L5))));
		Vector256<ulong> k5 = state.Q.L5;
		state.P.L5 = Blend2(Avx2.Permute4x64(Blend0((u5 & Vector256.Create(SM2Field29.Mask)) + (u4 >> SM2Field29.Bits), f5), 0xE8), Broadcast0(k5));
		state.Q.L5 = Blend3(k5, Broadcast0(f5));
		Vector256<ulong> f6 = sixth.L6;
		Vector256<ulong> y6 = f6 + Vector256.Create(SM2Field29.FourPMiddle) - Swap(f6);
		Vector256<ulong> u6 = Vector256.ConditionalSelect(zero, state.P.L6, Vector256.ConditionalSelect(infinity, entry.EA.L6, Blend3(y6, Broadcast0(fourth.L6))));
		Vector256<ulong> k6 = state.Q.L6;
		state.P.L6 = Blend2(Avx2.Permute4x64(Blend0((u6 & Vector256.Create(SM2Field29.Mask)) + (u5 >> SM2Field29.Bits), f6), 0xE8), Broadcast0(k6));
		state.Q.L6 = Blend3(k6, Broadcast0(f6));
		Vector256<ulong> f7 = sixth.L7;
		Vector256<ulong> y7 = f7 + Vector256.Create(SM2Field29.FourP7) - Swap(f7) + (j << 21);
		Vector256<ulong> u7 = Vector256.ConditionalSelect(zero, state.P.L7, Vector256.ConditionalSelect(infinity, entry.EA.L7, Blend3(y7, Broadcast0(fourth.L7))));
		Vector256<ulong> k7 = state.Q.L7;
		state.P.L7 = Blend2(Avx2.Permute4x64(Blend0((u7 & Vector256.Create(SM2Field29.Mask)) + (u6 >> SM2Field29.Bits), f7), 0xE8), Broadcast0(k7));
		state.Q.L7 = Blend3(k7, Broadcast0(f7));
		Vector256<ulong> u8 = Vector256.ConditionalSelect(zero, state.P.L8, Vector256.ConditionalSelect(infinity, entry.EA.L8, Blend3(y8, Broadcast0(fourth.L8))));
		Vector256<ulong> k8 = state.Q.L8;
		state.P.L8 = Blend2(Avx2.Permute4x64(Blend0(u8 + (u7 >> SM2Field29.Bits), f8), 0xE8), Broadcast0(k8));
		state.Q.L8 = Blend3(k8, Broadcast0(f8));
	}


	// The entry of digit, read by a masked scan of the table, with Y negated as 4p − Y for a digit below 0; a digit of 0 gives zeros, which the masks discard.
	private static void Select(ReadOnlySpan<ulong> table, int digit, Span<ulong> packed, Span<ulong> negative, out SM2QuadEntry entry)
	{
		int sign = digit >> 31;
		Lookup(in table[0], (uint)((digit ^ sign) - sign) - 1, ref packed[0]);
		Unpack(ref packed[0], out entry);
		// Y alone, in lane 2 of EA.
		negative.Clear();
		negative[2] = (ulong)sign;
		SM2Field29x4Avx2.ConditionalNegate(in negative[0], ref entry.EA);
	}

	// Entry index of the table, to result, or zeros for an index beyond it, in one scan that reads every limb of every entry once and keeps what matches the index under a mask, so that neither the time nor the addresses depend on the index; each entry takes one comparison for all its blocks. The last block of an entry overlaps the one before it, and both write the same values to the shared limbs.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Lookup(ref readonly ulong table, uint index, ref ulong result)
	{
		Vector256<ulong> target = Vector256.Create((ulong)index);
		Vector256<ulong> position = Vector256<ulong>.Zero;
		Vector256<ulong> a0 = Vector256<ulong>.Zero;
		Vector256<ulong> a1 = a0;
		Vector256<ulong> a2 = a0;
		Vector256<ulong> a3 = a0;
		Vector256<ulong> a4 = a0;
		Vector256<ulong> a5 = a0;
		Vector256<ulong> a6 = a0;
		ref ulong entry = ref Unsafe.AsRef(in table);

		for (int j = 0; j < TableLength; ++j)
		{
			Vector256<ulong> mask = Vector256.Equals(position, target);
			a0 |= Vector256.LoadUnsafe(ref entry) & mask;
			a1 |= Vector256.LoadUnsafe(ref entry, 4) & mask;
			a2 |= Vector256.LoadUnsafe(ref entry, 8) & mask;
			a3 |= Vector256.LoadUnsafe(ref entry, 12) & mask;
			a4 |= Vector256.LoadUnsafe(ref entry, 16) & mask;
			a5 |= Vector256.LoadUnsafe(ref entry, 20) & mask;
			a6 |= Vector256.LoadUnsafe(ref entry, EntryLength - 4) & mask;
			position += Vector256<ulong>.One;
			entry = ref Unsafe.Add(ref entry, EntryLength);
		}

		a0.StoreUnsafe(ref result);
		a1.StoreUnsafe(ref result, 4);
		a2.StoreUnsafe(ref result, 8);
		a3.StoreUnsafe(ref result, 12);
		a4.StoreUnsafe(ref result, 16);
		a5.StoreUnsafe(ref result, 20);
		a6.StoreUnsafe(ref result, EntryLength - 4);
	}

	// An entry of EntryLength limbs at source as EA = [Z², X, Y, Z] and EB = [X, Z², Z³, Z³].
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void Unpack(ref ulong source, out SM2QuadEntry entry)
	{
		Unsafe.SkipInit(out entry);
		Vector256<ulong> mask = Vector256.Create(SM2Field29.Mask);
		Vector128<ulong> xy0 = Vector128.LoadUnsafe(ref source, 0);
		Vector128<ulong> cz0 = Vector128.LoadUnsafe(ref source, CubeOffset + 0);
		Vector128<ulong> s0 = Vector128.CreateScalar(Unsafe.Add(ref source, SquareOffset + 0));
		Vector256<ulong> a0 = Vector256.Create(Sse2.UnpackLow(s0, xy0), Sse2.UnpackHigh(xy0, cz0));
		Vector256<ulong> b0 = Vector256.Create(Sse2.UnpackLow(xy0, s0), Sse2.UnpackLow(cz0, cz0));
		entry.EA.L0 = a0 & mask;
		entry.EA.L1 = a0 >> SM2Field29.Bits;
		entry.EB.L0 = b0 & mask;
		entry.EB.L1 = b0 >> SM2Field29.Bits;
		Vector128<ulong> xy2 = Vector128.LoadUnsafe(ref source, 2);
		Vector128<ulong> cz2 = Vector128.LoadUnsafe(ref source, CubeOffset + 2);
		Vector128<ulong> s2 = Vector128.CreateScalar(Unsafe.Add(ref source, SquareOffset + 1));
		Vector256<ulong> a2 = Vector256.Create(Sse2.UnpackLow(s2, xy2), Sse2.UnpackHigh(xy2, cz2));
		Vector256<ulong> b2 = Vector256.Create(Sse2.UnpackLow(xy2, s2), Sse2.UnpackLow(cz2, cz2));
		entry.EA.L2 = a2 & mask;
		entry.EA.L3 = a2 >> SM2Field29.Bits;
		entry.EB.L2 = b2 & mask;
		entry.EB.L3 = b2 >> SM2Field29.Bits;
		Vector128<ulong> xy4 = Vector128.LoadUnsafe(ref source, 4);
		Vector128<ulong> cz4 = Vector128.LoadUnsafe(ref source, CubeOffset + 4);
		Vector128<ulong> s4 = Vector128.CreateScalar(Unsafe.Add(ref source, SquareOffset + 2));
		Vector256<ulong> a4 = Vector256.Create(Sse2.UnpackLow(s4, xy4), Sse2.UnpackHigh(xy4, cz4));
		Vector256<ulong> b4 = Vector256.Create(Sse2.UnpackLow(xy4, s4), Sse2.UnpackLow(cz4, cz4));
		entry.EA.L4 = a4 & mask;
		entry.EA.L5 = a4 >> SM2Field29.Bits;
		entry.EB.L4 = b4 & mask;
		entry.EB.L5 = b4 >> SM2Field29.Bits;
		Vector128<ulong> xy6 = Vector128.LoadUnsafe(ref source, 6);
		Vector128<ulong> cz6 = Vector128.LoadUnsafe(ref source, CubeOffset + 6);
		Vector128<ulong> s6 = Vector128.CreateScalar(Unsafe.Add(ref source, SquareOffset + 3));
		Vector256<ulong> a6 = Vector256.Create(Sse2.UnpackLow(s6, xy6), Sse2.UnpackHigh(xy6, cz6));
		Vector256<ulong> b6 = Vector256.Create(Sse2.UnpackLow(xy6, s6), Sse2.UnpackLow(cz6, cz6));
		entry.EA.L6 = a6 & mask;
		entry.EA.L7 = a6 >> SM2Field29.Bits;
		entry.EB.L6 = b6 & mask;
		entry.EB.L7 = b6 >> SM2Field29.Bits;
		Vector128<ulong> xy8 = Vector128.LoadUnsafe(ref source, 8);
		Vector128<ulong> cz8 = Vector128.LoadUnsafe(ref source, CubeOffset + 8);
		Vector128<ulong> s8 = Vector128.CreateScalar(Unsafe.Add(ref source, SquareOffset + 4));
		Vector256<ulong> a8 = Vector256.Create(Sse2.UnpackLow(s8, xy8), Sse2.UnpackHigh(xy8, cz8));
		Vector256<ulong> b8 = Vector256.Create(Sse2.UnpackLow(xy8, s8), Sse2.UnpackLow(cz8, cz8));
		entry.EA.L8 = a8;
		entry.EB.L8 = b8;
	}

	// The point of a state in the form E of SM2Field52: Halve and Reduce take the a·2^261 of the lanes to the a·2^260 of SM2Field52.
	internal static void ToJacobian(in SM2QuadState state, out JacobianPoint<SM2Field52> result)
	{
		SM2Field29x4Avx2.Halve(in state.P, out SM2Field29x4Avx2 p);
		SM2Field29x4Avx2.Reduce(in p, out p);
		Lane(in p, 2, out result.X);
		Lane(in p, 1, out result.Y);
		Lane(in p, 3, out result.Z);
	}

	// k·Q for a public k below n by the NAF of u2 in ECVariableTimeGroup.MultiplyAdd, with the odd multiples of Q that BuildOddMultiples gives. The time and the branches depend on k and Q.
	[SkipLocalsInit]
	internal static void MultiplyVariableTime(in AffinePoint<SM2Field52> point, in FieldElement<SM2Order> scalar, out JacobianPoint<SM2Field52> result)
	{
		Span<sbyte> digits = stackalloc sbyte[ECVariableTimeGroup<SM2Curve, SM2Field52, SM2Order>.DigitCount];
		int top = ECVariableTimeGroup<SM2Curve, SM2Field52, SM2Order>.Recode(in scalar, PointWidth, digits);
		Span<SM2QuadEntry> multiples = stackalloc SM2QuadEntry[OddLength];
		Span<ulong> negative = [0, 0, ulong.MaxValue, 0];
		BuildOddMultiples(in point, multiples);
		Unsafe.SkipInit(out SM2QuadState total);
		bool infinity = true;
		int doublings = 0;

		for (int i = top; i >= 0; --i)
		{
			if (!infinity)
			{
				++doublings;
			}

			int digit = digits[i];

			if (digit is not 0)
			{
				Double(ref total, doublings);
				doublings = 0;
				SM2QuadEntry entry = multiples[Math.Abs(digit) >> 1];

				if (digit < 0)
				{
					SM2Field29x4Avx2.ConditionalNegate(in negative[0], ref entry.EA);
				}

				AddVariableTime(ref total, ref infinity, in entry);
			}
		}

		if (infinity)
		{
			result = default;
			return;
		}

		Double(ref total, doublings);
		ToJacobian(in total, out result);
	}

	// Q, 3Q, …, 15Q: (j + 2)·Q = j·Q + 2Q by AddState, additions of points neither equal nor opposite, as j + 2 < n and j ≠ 2.
	[SkipLocalsInit]
	private static void BuildOddMultiples(in AffinePoint<SM2Field52> point, Span<SM2QuadEntry> entries)
	{
		Span<SM2QuadState> sums = stackalloc SM2QuadState[2];
		ToEntry(in point, out entries[0]);
		FromEntry(in entries[0], out sums[0]);
		sums[1] = sums[0];
		DoubleOnce(ref sums[1]);
		ToEntry(in sums[1], out SM2QuadEntry step);

		for (int j = 1; j < OddLength; ++j)
		{
			AddState(ref sums[0], in step);
			ToEntry(in sums[0], out entries[j]);
		}
	}

	// Sets bases[i] to 2^(wi)·P for w = width, each through ToJacobian, from one chain of doublings on the lanes; no base is the point at infinity, as 2^(wi) is no multiple of n. P is public, so nothing is cleared.
	internal static void FillBases(in AffinePoint<SM2Field52> point, int width, Span<JacobianPoint<SM2Field52>> bases)
	{
		ToEntry(in point, out SM2QuadEntry entry);
		FromEntry(in entry, out SM2QuadState state);
		JacobianPoint<SM2Field52>.FromAffine(in point, out bases[0]);

		for (int i = 1; i < bases.Length; ++i)
		{
			Double(ref state, width);
			ToJacobian(in state, out bases[i]);
		}
	}

	// count doublings, two by each DoubleTwice and the odd one by DoubleOnce.
	private static void Double(ref SM2QuadState state, int count)
	{
		DoubleTwice(ref state, count / 2);

		if (count % 2 is not 0)
		{
			DoubleOnce(ref state);
		}
	}

	// total + entry, where total may be the point at infinity, which infinity tells, and the points may be equal or opposite. Z3 = Z1·Z2·H of AddState is 0 just for H = 0, so for equal or opposite points, which its formulas do not cover; then the formulas of SM2Field52 tell them apart. The points are public, so the cases may branch.
	[SkipLocalsInit]
	private static void AddVariableTime(ref SM2QuadState total, ref bool infinity, in SM2QuadEntry entry)
	{
		if (infinity)
		{
			FromEntry(in entry, out total);
			infinity = false;
			return;
		}

		SM2QuadState left = total;
		AddState(ref total, in entry);

		if (!IsZeroZ(in total))
		{
			return;
		}

		ToJacobian(in left, out JacobianPoint<SM2Field52> x);
		ToJacobian(in entry, out JacobianPoint<SM2Field52> y);

		if (ECGroup<SM2Curve, SM2Field52, SM2Order>.AddDistinct(in x, in y, out _) is 0)
		{
			infinity = true;
			return;
		}

		DoubleOnce(ref left);
		total = left;
	}

	// Whether Z, in lane 3 of P, is 0 mod p: below 2p in limbs 0 to 7 below 2^29 once reduced, its limbs then are those of 0 or of p.
	private static bool IsZeroZ(in SM2QuadState state)
	{
		SM2Field29x4Avx2.Reduce(in state.P, out SM2Field29x4Avx2 z);
		Vector256<ulong> low = Vector256.Create(SM2Field29.PLow);
		Vector256<ulong> zero = z.L0 | z.L1 | z.L2 | z.L3 | z.L4 | z.L5 | z.L6 | z.L7 | z.L8;
		Vector256<ulong> modulus = z.L0 ^ low | z.L1 ^ low | z.L2 ^ Vector256.Create(SM2Field29.P2) | z.L3 ^ Vector256.Create(SM2Field29.P3) | z.L4 ^ low | z.L5 ^ low | z.L6 ^ low | z.L7 ^ Vector256.Create(SM2Field29.P7) | z.L8 ^ Vector256.Create(SM2Field29.P8);
		return zero.GetElement(3) is 0 || modulus.GetElement(3) is 0;
	}

	// state + entry in four rounds, the rounds A0 to A3 of DoubleAdd with the point of the state for the double and no masks, for an entry neither equal nor opposite to the point, and neither of them the point at infinity. With X1, Y1 and Z1 of the state within its bounds, the products of A0 and S1 and S2 are below 1.3p, the other bounds of DoubleAdd hold, and α, of X3 as Reduce leaves it, is below 2p; Y3, folded, and Z3 go to the state carried.
	[SkipLocalsInit]
	internal static void AddState(ref SM2QuadState state, in SM2QuadEntry entry)
	{
		Unsafe.SkipInit(out SM2Field29x4Avx2 left);
		Unsafe.SkipInit(out SM2Field29x4Avx2 right);
		Unsafe.SkipInit(out SM2Field29x4Avx2 next);
		left.L0 = Blend23(state.Q.L0, Broadcast3(state.P.L0));
		left.L1 = Blend23(state.Q.L1, Broadcast3(state.P.L1));
		left.L2 = Blend23(state.Q.L2, Broadcast3(state.P.L2));
		left.L3 = Blend23(state.Q.L3, Broadcast3(state.P.L3));
		left.L4 = Blend23(state.Q.L4, Broadcast3(state.P.L4));
		left.L5 = Blend23(state.Q.L5, Broadcast3(state.P.L5));
		left.L6 = Blend23(state.Q.L6, Broadcast3(state.P.L6));
		left.L7 = Blend23(state.Q.L7, Broadcast3(state.P.L7));
		left.L8 = Blend23(state.Q.L8, Broadcast3(state.P.L8));
		SM2Field29x4Avx2.Multiply(in left, in entry.EA, out SM2Field29x4Avx2 third);
		// The right of A1, [H, H, δ1, Z2³], carried.
		Vector256<ulong> c0 = third.L0;
		Vector256<ulong> d0 = c0 + Vector256.Create(SM2Field29.FourP0) - Swap(c0);
		left.L0 = Blend23(Blend1(Broadcast3(c0), d0), Blend3(c0, Avx2.Permute4x64(state.P.L0, 0x40)));
		Vector256<ulong> o0 = Blend3(Blend2(Avx2.UnpackHigh(d0, d0), Broadcast1(state.Q.L0)), entry.EB.L0);
		right.L0 = o0 & Vector256.Create(SM2Field29.Mask);
		Vector256<ulong> c1 = third.L1;
		Vector256<ulong> d1 = c1 + Vector256.Create(SM2Field29.FourP1) - Swap(c1);
		left.L1 = Blend23(Blend1(Broadcast3(c1), d1), Blend3(c1, Avx2.Permute4x64(state.P.L1, 0x40)));
		Vector256<ulong> o1 = Blend3(Blend2(Avx2.UnpackHigh(d1, d1), Broadcast1(state.Q.L1)), entry.EB.L1);
		right.L1 = (o1 & Vector256.Create(SM2Field29.Mask)) + (o0 >> SM2Field29.Bits);
		Vector256<ulong> c2 = third.L2;
		Vector256<ulong> d2 = c2 + Vector256.Create(SM2Field29.FourP2) - Swap(c2);
		left.L2 = Blend23(Blend1(Broadcast3(c2), d2), Blend3(c2, Avx2.Permute4x64(state.P.L2, 0x40)));
		Vector256<ulong> o2 = Blend3(Blend2(Avx2.UnpackHigh(d2, d2), Broadcast1(state.Q.L2)), entry.EB.L2);
		right.L2 = (o2 & Vector256.Create(SM2Field29.Mask)) + (o1 >> SM2Field29.Bits);
		Vector256<ulong> c3 = third.L3;
		Vector256<ulong> d3 = c3 + Vector256.Create(SM2Field29.FourP3) - Swap(c3);
		left.L3 = Blend23(Blend1(Broadcast3(c3), d3), Blend3(c3, Avx2.Permute4x64(state.P.L3, 0x40)));
		Vector256<ulong> o3 = Blend3(Blend2(Avx2.UnpackHigh(d3, d3), Broadcast1(state.Q.L3)), entry.EB.L3);
		right.L3 = (o3 & Vector256.Create(SM2Field29.Mask)) + (o2 >> SM2Field29.Bits);
		Vector256<ulong> c4 = third.L4;
		Vector256<ulong> d4 = c4 + Vector256.Create(SM2Field29.FourPMiddle) - Swap(c4);
		left.L4 = Blend23(Blend1(Broadcast3(c4), d4), Blend3(c4, Avx2.Permute4x64(state.P.L4, 0x40)));
		Vector256<ulong> o4 = Blend3(Blend2(Avx2.UnpackHigh(d4, d4), Broadcast1(state.Q.L4)), entry.EB.L4);
		right.L4 = (o4 & Vector256.Create(SM2Field29.Mask)) + (o3 >> SM2Field29.Bits);
		Vector256<ulong> c5 = third.L5;
		Vector256<ulong> d5 = c5 + Vector256.Create(SM2Field29.FourPMiddle) - Swap(c5);
		left.L5 = Blend23(Blend1(Broadcast3(c5), d5), Blend3(c5, Avx2.Permute4x64(state.P.L5, 0x40)));
		Vector256<ulong> o5 = Blend3(Blend2(Avx2.UnpackHigh(d5, d5), Broadcast1(state.Q.L5)), entry.EB.L5);
		right.L5 = (o5 & Vector256.Create(SM2Field29.Mask)) + (o4 >> SM2Field29.Bits);
		Vector256<ulong> c6 = third.L6;
		Vector256<ulong> d6 = c6 + Vector256.Create(SM2Field29.FourPMiddle) - Swap(c6);
		left.L6 = Blend23(Blend1(Broadcast3(c6), d6), Blend3(c6, Avx2.Permute4x64(state.P.L6, 0x40)));
		Vector256<ulong> o6 = Blend3(Blend2(Avx2.UnpackHigh(d6, d6), Broadcast1(state.Q.L6)), entry.EB.L6);
		right.L6 = (o6 & Vector256.Create(SM2Field29.Mask)) + (o5 >> SM2Field29.Bits);
		Vector256<ulong> c7 = third.L7;
		Vector256<ulong> d7 = c7 + Vector256.Create(SM2Field29.FourP7) - Swap(c7);
		left.L7 = Blend23(Blend1(Broadcast3(c7), d7), Blend3(c7, Avx2.Permute4x64(state.P.L7, 0x40)));
		Vector256<ulong> o7 = Blend3(Blend2(Avx2.UnpackHigh(d7, d7), Broadcast1(state.Q.L7)), entry.EB.L7);
		right.L7 = (o7 & Vector256.Create(SM2Field29.Mask)) + (o6 >> SM2Field29.Bits);
		Vector256<ulong> c8 = third.L8;
		Vector256<ulong> d8 = c8 + Vector256.Create(SM2Field29.FourP8) - Swap(c8);
		left.L8 = Blend23(Blend1(Broadcast3(c8), d8), Blend3(c8, Avx2.Permute4x64(state.P.L8, 0x40)));
		Vector256<ulong> o8 = Blend3(Blend2(Avx2.UnpackHigh(d8, d8), Broadcast1(state.Q.L8)), entry.EB.L8);
		right.L8 = o8 + (o7 >> SM2Field29.Bits);
		SM2Field29x4Avx2.Multiply(in left, in right, out SM2Field29x4Avx2 fourth);
		// R carried, in the lanes 2 of both operands of A2; H from lane 1 of the right of A1, read before right takes that of A2.
		Vector256<ulong> b0 = fourth.L0;
		Vector256<ulong> r0 = b0 + Vector256.Create(SM2Field29.FourP0) - Swap(b0);
		Vector256<ulong> q0 = Blend3(r0 & Vector256.Create(SM2Field29.Mask), Broadcast0(b0));
		left.L0 = Blend23(Blend1(third.L0, right.L0), q0);
		right.L0 = Blend23(Avx2.UnpackHigh(b0, b0), q0);
		Vector256<ulong> b1 = fourth.L1;
		Vector256<ulong> r1 = b1 + Vector256.Create(SM2Field29.FourP1) - Swap(b1);
		Vector256<ulong> q1 = Blend3((r1 & Vector256.Create(SM2Field29.Mask)) + (r0 >> SM2Field29.Bits), Broadcast0(b1));
		left.L1 = Blend23(Blend1(third.L1, right.L1), q1);
		right.L1 = Blend23(Avx2.UnpackHigh(b1, b1), q1);
		Vector256<ulong> b2 = fourth.L2;
		Vector256<ulong> r2 = b2 + Vector256.Create(SM2Field29.FourP2) - Swap(b2);
		Vector256<ulong> q2 = Blend3((r2 & Vector256.Create(SM2Field29.Mask)) + (r1 >> SM2Field29.Bits), Broadcast0(b2));
		left.L2 = Blend23(Blend1(third.L2, right.L2), q2);
		right.L2 = Blend23(Avx2.UnpackHigh(b2, b2), q2);
		Vector256<ulong> b3 = fourth.L3;
		Vector256<ulong> r3 = b3 + Vector256.Create(SM2Field29.FourP3) - Swap(b3);
		Vector256<ulong> q3 = Blend3((r3 & Vector256.Create(SM2Field29.Mask)) + (r2 >> SM2Field29.Bits), Broadcast0(b3));
		left.L3 = Blend23(Blend1(third.L3, right.L3), q3);
		right.L3 = Blend23(Avx2.UnpackHigh(b3, b3), q3);
		Vector256<ulong> b4 = fourth.L4;
		Vector256<ulong> r4 = b4 + Vector256.Create(SM2Field29.FourPMiddle) - Swap(b4);
		Vector256<ulong> q4 = Blend3((r4 & Vector256.Create(SM2Field29.Mask)) + (r3 >> SM2Field29.Bits), Broadcast0(b4));
		left.L4 = Blend23(Blend1(third.L4, right.L4), q4);
		right.L4 = Blend23(Avx2.UnpackHigh(b4, b4), q4);
		Vector256<ulong> b5 = fourth.L5;
		Vector256<ulong> r5 = b5 + Vector256.Create(SM2Field29.FourPMiddle) - Swap(b5);
		Vector256<ulong> q5 = Blend3((r5 & Vector256.Create(SM2Field29.Mask)) + (r4 >> SM2Field29.Bits), Broadcast0(b5));
		left.L5 = Blend23(Blend1(third.L5, right.L5), q5);
		right.L5 = Blend23(Avx2.UnpackHigh(b5, b5), q5);
		Vector256<ulong> b6 = fourth.L6;
		Vector256<ulong> r6 = b6 + Vector256.Create(SM2Field29.FourPMiddle) - Swap(b6);
		Vector256<ulong> q6 = Blend3((r6 & Vector256.Create(SM2Field29.Mask)) + (r5 >> SM2Field29.Bits), Broadcast0(b6));
		left.L6 = Blend23(Blend1(third.L6, right.L6), q6);
		right.L6 = Blend23(Avx2.UnpackHigh(b6, b6), q6);
		Vector256<ulong> b7 = fourth.L7;
		Vector256<ulong> r7 = b7 + Vector256.Create(SM2Field29.FourP7) - Swap(b7);
		Vector256<ulong> q7 = Blend3((r7 & Vector256.Create(SM2Field29.Mask)) + (r6 >> SM2Field29.Bits), Broadcast0(b7));
		left.L7 = Blend23(Blend1(third.L7, right.L7), q7);
		right.L7 = Blend23(Avx2.UnpackHigh(b7, b7), q7);
		Vector256<ulong> b8 = fourth.L8;
		Vector256<ulong> r8 = b8 + Vector256.Create(SM2Field29.FourP8) - Swap(b8);
		Vector256<ulong> q8 = Blend3(r8 + (r7 >> SM2Field29.Bits), Broadcast0(b8));
		left.L8 = Blend23(Blend1(third.L8, right.L8), q8);
		right.L8 = Blend23(Avx2.UnpackHigh(b8, b8), q8);
		// fifth and sixth take the buffer of third once no later step reads what it held, so that the frame stays under a page.
		ref SM2Field29x4Avx2 fifth = ref third;
		SM2Field29x4Avx2.Multiply(in left, in right, out fifth);
		Vector256<ulong> e0 = fifth.L0;
		Vector256<ulong> p0 = Broadcast0(e0);
		Vector256<ulong> n0 = Broadcast1(e0);
		next.L0 = e0 + Vector256.Create(3 * SM2Field29.FourP0) - (n0 + (p0 << 1));
		// The right of A3 takes W and H3 here and 3(X + δ) in lane 0 below.
		right.L0 = Blend3((p0 << 1) + p0 + n0 + Vector256.Create(SM2Field29.FourP0) - e0, n0);
		Vector256<ulong> e1 = fifth.L1;
		Vector256<ulong> p1 = Broadcast0(e1);
		Vector256<ulong> n1 = Broadcast1(e1);
		next.L1 = e1 + Vector256.Create(3 * SM2Field29.FourP1) - (n1 + (p1 << 1));
		right.L1 = Blend3((p1 << 1) + p1 + n1 + Vector256.Create(SM2Field29.FourP1) - e1, n1);
		Vector256<ulong> e2 = fifth.L2;
		Vector256<ulong> p2 = Broadcast0(e2);
		Vector256<ulong> n2 = Broadcast1(e2);
		next.L2 = e2 + Vector256.Create(3 * SM2Field29.FourP2) - (n2 + (p2 << 1));
		right.L2 = Blend3((p2 << 1) + p2 + n2 + Vector256.Create(SM2Field29.FourP2) - e2, n2);
		Vector256<ulong> e3 = fifth.L3;
		Vector256<ulong> p3 = Broadcast0(e3);
		Vector256<ulong> n3 = Broadcast1(e3);
		next.L3 = e3 + Vector256.Create(3 * SM2Field29.FourP3) - (n3 + (p3 << 1));
		right.L3 = Blend3((p3 << 1) + p3 + n3 + Vector256.Create(SM2Field29.FourP3) - e3, n3);
		Vector256<ulong> e4 = fifth.L4;
		Vector256<ulong> p4 = Broadcast0(e4);
		Vector256<ulong> n4 = Broadcast1(e4);
		next.L4 = e4 + Vector256.Create(3 * SM2Field29.FourPMiddle) - (n4 + (p4 << 1));
		right.L4 = Blend3((p4 << 1) + p4 + n4 + Vector256.Create(SM2Field29.FourPMiddle) - e4, n4);
		Vector256<ulong> e5 = fifth.L5;
		Vector256<ulong> p5 = Broadcast0(e5);
		Vector256<ulong> n5 = Broadcast1(e5);
		next.L5 = e5 + Vector256.Create(3 * SM2Field29.FourPMiddle) - (n5 + (p5 << 1));
		right.L5 = Blend3((p5 << 1) + p5 + n5 + Vector256.Create(SM2Field29.FourPMiddle) - e5, n5);
		Vector256<ulong> e6 = fifth.L6;
		Vector256<ulong> p6 = Broadcast0(e6);
		Vector256<ulong> n6 = Broadcast1(e6);
		next.L6 = e6 + Vector256.Create(3 * SM2Field29.FourPMiddle) - (n6 + (p6 << 1));
		right.L6 = Blend3((p6 << 1) + p6 + n6 + Vector256.Create(SM2Field29.FourPMiddle) - e6, n6);
		Vector256<ulong> e7 = fifth.L7;
		Vector256<ulong> p7 = Broadcast0(e7);
		Vector256<ulong> n7 = Broadcast1(e7);
		next.L7 = e7 + Vector256.Create(3 * SM2Field29.FourP7) - (n7 + (p7 << 1));
		right.L7 = Blend3((p7 << 1) + p7 + n7 + Vector256.Create(SM2Field29.FourP7) - e7, n7);
		Vector256<ulong> e8 = fifth.L8;
		Vector256<ulong> p8 = Broadcast0(e8);
		Vector256<ulong> n8 = Broadcast1(e8);
		next.L8 = e8 + Vector256.Create(3 * SM2Field29.FourP8) - (n8 + (p8 << 1));
		right.L8 = Blend3((p8 << 1) + p8 + n8 + Vector256.Create(SM2Field29.FourP8) - e8, n8);
		SM2Field29x4Avx2.Reduce(in next, out next);
		// The right of A3 carried.
		Vector256<ulong> x0 = Avx2.Permute4x64(Blend3(next.L0, fifth.L0), 0xEE);
		Vector256<ulong> m0 = Swap(x0);
		Vector256<ulong> t0 = x0 + m0;
		// The state, whose point no later round reads, keeps the X and δ of the sum in Q, and R comes from lane 2 of the left of A2.
		state.Q.L0 = x0;
		left.L0 = Blend0(Blend3(left.L0, fourth.L0), x0 + Vector256.Create(SM2Field29.FourP0) - m0);
		Vector256<ulong> w0 = Blend0(right.L0, t0 + (t0 << 1));
		right.L0 = w0 & Vector256.Create(SM2Field29.Mask);
		Vector256<ulong> x1 = Avx2.Permute4x64(Blend3(next.L1, fifth.L1), 0xEE);
		Vector256<ulong> m1 = Swap(x1);
		Vector256<ulong> t1 = x1 + m1;
		state.Q.L1 = x1;
		left.L1 = Blend0(Blend3(left.L1, fourth.L1), x1 + Vector256.Create(SM2Field29.FourP1) - m1);
		Vector256<ulong> w1 = Blend0(right.L1, t1 + (t1 << 1));
		right.L1 = (w1 & Vector256.Create(SM2Field29.Mask)) + (w0 >> SM2Field29.Bits);
		Vector256<ulong> x2 = Avx2.Permute4x64(Blend3(next.L2, fifth.L2), 0xEE);
		Vector256<ulong> m2 = Swap(x2);
		Vector256<ulong> t2 = x2 + m2;
		state.Q.L2 = x2;
		left.L2 = Blend0(Blend3(left.L2, fourth.L2), x2 + Vector256.Create(SM2Field29.FourP2) - m2);
		Vector256<ulong> w2 = Blend0(right.L2, t2 + (t2 << 1));
		right.L2 = (w2 & Vector256.Create(SM2Field29.Mask)) + (w1 >> SM2Field29.Bits);
		Vector256<ulong> x3 = Avx2.Permute4x64(Blend3(next.L3, fifth.L3), 0xEE);
		Vector256<ulong> m3 = Swap(x3);
		Vector256<ulong> t3 = x3 + m3;
		state.Q.L3 = x3;
		left.L3 = Blend0(Blend3(left.L3, fourth.L3), x3 + Vector256.Create(SM2Field29.FourP3) - m3);
		Vector256<ulong> w3 = Blend0(right.L3, t3 + (t3 << 1));
		right.L3 = (w3 & Vector256.Create(SM2Field29.Mask)) + (w2 >> SM2Field29.Bits);
		Vector256<ulong> x4 = Avx2.Permute4x64(Blend3(next.L4, fifth.L4), 0xEE);
		Vector256<ulong> m4 = Swap(x4);
		Vector256<ulong> t4 = x4 + m4;
		state.Q.L4 = x4;
		left.L4 = Blend0(Blend3(left.L4, fourth.L4), x4 + Vector256.Create(SM2Field29.FourPMiddle) - m4);
		Vector256<ulong> w4 = Blend0(right.L4, t4 + (t4 << 1));
		right.L4 = (w4 & Vector256.Create(SM2Field29.Mask)) + (w3 >> SM2Field29.Bits);
		Vector256<ulong> x5 = Avx2.Permute4x64(Blend3(next.L5, fifth.L5), 0xEE);
		Vector256<ulong> m5 = Swap(x5);
		Vector256<ulong> t5 = x5 + m5;
		state.Q.L5 = x5;
		left.L5 = Blend0(Blend3(left.L5, fourth.L5), x5 + Vector256.Create(SM2Field29.FourPMiddle) - m5);
		Vector256<ulong> w5 = Blend0(right.L5, t5 + (t5 << 1));
		right.L5 = (w5 & Vector256.Create(SM2Field29.Mask)) + (w4 >> SM2Field29.Bits);
		Vector256<ulong> x6 = Avx2.Permute4x64(Blend3(next.L6, fifth.L6), 0xEE);
		Vector256<ulong> m6 = Swap(x6);
		Vector256<ulong> t6 = x6 + m6;
		state.Q.L6 = x6;
		left.L6 = Blend0(Blend3(left.L6, fourth.L6), x6 + Vector256.Create(SM2Field29.FourPMiddle) - m6);
		Vector256<ulong> w6 = Blend0(right.L6, t6 + (t6 << 1));
		right.L6 = (w6 & Vector256.Create(SM2Field29.Mask)) + (w5 >> SM2Field29.Bits);
		Vector256<ulong> x7 = Avx2.Permute4x64(Blend3(next.L7, fifth.L7), 0xEE);
		Vector256<ulong> m7 = Swap(x7);
		Vector256<ulong> t7 = x7 + m7;
		state.Q.L7 = x7;
		left.L7 = Blend0(Blend3(left.L7, fourth.L7), x7 + Vector256.Create(SM2Field29.FourP7) - m7);
		Vector256<ulong> w7 = Blend0(right.L7, t7 + (t7 << 1));
		right.L7 = (w7 & Vector256.Create(SM2Field29.Mask)) + (w6 >> SM2Field29.Bits);
		Vector256<ulong> x8 = Avx2.Permute4x64(Blend3(next.L8, fifth.L8), 0xEE);
		Vector256<ulong> m8 = Swap(x8);
		Vector256<ulong> t8 = x8 + m8;
		state.Q.L8 = x8;
		left.L8 = Blend0(Blend3(left.L8, fourth.L8), x8 + Vector256.Create(SM2Field29.FourP8) - m8);
		Vector256<ulong> w8 = Blend0(right.L8, t8 + (t8 << 1));
		right.L8 = w8 + (w7 >> SM2Field29.Bits);
		ref SM2Field29x4Avx2 sixth = ref third;
		SM2Field29x4Avx2.Multiply(in left, in right, out sixth);
		// Y3 folded, and Y3 and Z3 carried.
		Vector256<ulong> f8 = sixth.L8;
		Vector256<ulong> y8 = f8 + Vector256.Create(SM2Field29.FourP8) - Swap(f8);
		Vector256<ulong> j = y8 >> 24;
		y8 &= Vector256.Create(SM2Field29.TopMask);
		Vector256<ulong> f0 = sixth.L0;
		Vector256<ulong> y0 = f0 + Vector256.Create(SM2Field29.FourP0) - Swap(f0) + j;
		Vector256<ulong> u0 = Blend3(y0, Broadcast0(fourth.L0));
		Vector256<ulong> k0 = state.Q.L0;
		state.P.L0 = Blend2(Avx2.Permute4x64(Blend0(u0 & Vector256.Create(SM2Field29.Mask), f0), 0xE8), Broadcast0(k0));
		state.Q.L0 = Blend3(k0, Broadcast0(f0));
		Vector256<ulong> f1 = sixth.L1;
		Vector256<ulong> y1 = f1 + Vector256.Create(SM2Field29.FourP1) - Swap(f1);
		Vector256<ulong> u1 = Blend3(y1, Broadcast0(fourth.L1));
		Vector256<ulong> k1 = state.Q.L1;
		state.P.L1 = Blend2(Avx2.Permute4x64(Blend0((u1 & Vector256.Create(SM2Field29.Mask)) + (u0 >> SM2Field29.Bits), f1), 0xE8), Broadcast0(k1));
		state.Q.L1 = Blend3(k1, Broadcast0(f1));
		Vector256<ulong> f2 = sixth.L2;
		Vector256<ulong> y2 = f2 + Vector256.Create(SM2Field29.FourPFold2) - Swap(f2) - (j << 6);
		Vector256<ulong> u2 = Blend3(y2, Broadcast0(fourth.L2));
		Vector256<ulong> k2 = state.Q.L2;
		state.P.L2 = Blend2(Avx2.Permute4x64(Blend0((u2 & Vector256.Create(SM2Field29.Mask)) + (u1 >> SM2Field29.Bits), f2), 0xE8), Broadcast0(k2));
		state.Q.L2 = Blend3(k2, Broadcast0(f2));
		Vector256<ulong> f3 = sixth.L3;
		Vector256<ulong> y3 = f3 + Vector256.Create(SM2Field29.FourPFold3) - Swap(f3) + (j << 9);
		Vector256<ulong> u3 = Blend3(y3, Broadcast0(fourth.L3));
		Vector256<ulong> k3 = state.Q.L3;
		state.P.L3 = Blend2(Avx2.Permute4x64(Blend0((u3 & Vector256.Create(SM2Field29.Mask)) + (u2 >> SM2Field29.Bits), f3), 0xE8), Broadcast0(k3));
		state.Q.L3 = Blend3(k3, Broadcast0(f3));
		Vector256<ulong> f4 = sixth.L4;
		Vector256<ulong> y4 = f4 + Vector256.Create(SM2Field29.FourPMiddle) - Swap(f4);
		Vector256<ulong> u4 = Blend3(y4, Broadcast0(fourth.L4));
		Vector256<ulong> k4 = state.Q.L4;
		state.P.L4 = Blend2(Avx2.Permute4x64(Blend0((u4 & Vector256.Create(SM2Field29.Mask)) + (u3 >> SM2Field29.Bits), f4), 0xE8), Broadcast0(k4));
		state.Q.L4 = Blend3(k4, Broadcast0(f4));
		Vector256<ulong> f5 = sixth.L5;
		Vector256<ulong> y5 = f5 + Vector256.Create(SM2Field29.FourPMiddle) - Swap(f5);
		Vector256<ulong> u5 = Blend3(y5, Broadcast0(fourth.L5));
		Vector256<ulong> k5 = state.Q.L5;
		state.P.L5 = Blend2(Avx2.Permute4x64(Blend0((u5 & Vector256.Create(SM2Field29.Mask)) + (u4 >> SM2Field29.Bits), f5), 0xE8), Broadcast0(k5));
		state.Q.L5 = Blend3(k5, Broadcast0(f5));
		Vector256<ulong> f6 = sixth.L6;
		Vector256<ulong> y6 = f6 + Vector256.Create(SM2Field29.FourPMiddle) - Swap(f6);
		Vector256<ulong> u6 = Blend3(y6, Broadcast0(fourth.L6));
		Vector256<ulong> k6 = state.Q.L6;
		state.P.L6 = Blend2(Avx2.Permute4x64(Blend0((u6 & Vector256.Create(SM2Field29.Mask)) + (u5 >> SM2Field29.Bits), f6), 0xE8), Broadcast0(k6));
		state.Q.L6 = Blend3(k6, Broadcast0(f6));
		Vector256<ulong> f7 = sixth.L7;
		Vector256<ulong> y7 = f7 + Vector256.Create(SM2Field29.FourP7) - Swap(f7) + (j << 21);
		Vector256<ulong> u7 = Blend3(y7, Broadcast0(fourth.L7));
		Vector256<ulong> k7 = state.Q.L7;
		state.P.L7 = Blend2(Avx2.Permute4x64(Blend0((u7 & Vector256.Create(SM2Field29.Mask)) + (u6 >> SM2Field29.Bits), f7), 0xE8), Broadcast0(k7));
		state.Q.L7 = Blend3(k7, Broadcast0(f7));
		Vector256<ulong> u8 = Blend3(y8, Broadcast0(fourth.L8));
		Vector256<ulong> k8 = state.Q.L8;
		state.P.L8 = Blend2(Avx2.Permute4x64(Blend0(u8 + (u7 >> SM2Field29.Bits), f8), 0xE8), Broadcast0(k8));
		state.Q.L8 = Blend3(k8, Broadcast0(f8));
	}


	// 2·point in three rounds: E0 and E1 of DoubleTwice and [α′, ·, ·, ·] of O0 alone, with their bounds; X′ and Y′ go to the state carried.
	[SkipLocalsInit]
	internal static void DoubleOnce(ref SM2QuadState state)
	{
		Unsafe.SkipInit(out SM2QuadScratch6 scratch);
		ref SM2Field29x4Avx2 left = ref AlignedScratch.Start<SM2QuadScratch6, SM2Field29x4Avx2>(ref scratch);
		ref SM2Field29x4Avx2 right = ref Unsafe.Add(ref left, 1);
		ref SM2Field29x4Avx2 xs = ref Unsafe.Add(ref left, 2);
		ref SM2Field29x4Avx2 first = ref Unsafe.Add(ref left, 3);
		ref SM2Field29x4Avx2 second = ref Unsafe.Add(ref left, 4);
		ref SM2Field29x4Avx2 third = ref Unsafe.Add(ref left, 5);
		left.L0 = Avx2.Permute4x64(state.P.L0, 0x44);
		left.L1 = Avx2.Permute4x64(state.P.L1, 0x44);
		left.L2 = Avx2.Permute4x64(state.P.L2, 0x44);
		left.L3 = Avx2.Permute4x64(state.P.L3, 0x44);
		left.L4 = Avx2.Permute4x64(state.P.L4, 0x44);
		left.L5 = Avx2.Permute4x64(state.P.L5, 0x44);
		left.L6 = Avx2.Permute4x64(state.P.L6, 0x44);
		left.L7 = Avx2.Permute4x64(state.P.L7, 0x44);
		left.L8 = Avx2.Permute4x64(state.P.L8, 0x44);
		SM2Field29x4Avx2.Multiply(in left, in state.P, out first);
		// The right of E1 carried.
		Vector256<ulong> a0 = first.L0;
		Vector256<ulong> g0 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a0, 0x15), Vector256.Create(3UL, 2, 2, 0));
		left.L0 = MaskedBlend2(state.Q.L0, a0 + (a0 << 1) + Vector256.Create(2 * SM2Field29.FourP0) - (g0 >> 1));
		right.L0 = g0 & Vector256.Create(SM2Field29.Mask);
		Vector256<ulong> a1 = first.L1;
		Vector256<ulong> g1 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a1, 0x15), Vector256.Create(3UL, 2, 2, 0));
		left.L1 = MaskedBlend2(state.Q.L1, a1 + (a1 << 1) + Vector256.Create(2 * SM2Field29.FourP1) - (g1 >> 1));
		right.L1 = (g1 & Vector256.Create(SM2Field29.Mask)) + (g0 >> SM2Field29.Bits);
		Vector256<ulong> a2 = first.L2;
		Vector256<ulong> g2 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a2, 0x15), Vector256.Create(3UL, 2, 2, 0));
		left.L2 = MaskedBlend2(state.Q.L2, a2 + (a2 << 1) + Vector256.Create(2 * SM2Field29.FourP2) - (g2 >> 1));
		right.L2 = (g2 & Vector256.Create(SM2Field29.Mask)) + (g1 >> SM2Field29.Bits);
		Vector256<ulong> a3 = first.L3;
		Vector256<ulong> g3 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a3, 0x15), Vector256.Create(3UL, 2, 2, 0));
		left.L3 = MaskedBlend2(state.Q.L3, a3 + (a3 << 1) + Vector256.Create(2 * SM2Field29.FourP3) - (g3 >> 1));
		right.L3 = (g3 & Vector256.Create(SM2Field29.Mask)) + (g2 >> SM2Field29.Bits);
		Vector256<ulong> a4 = first.L4;
		Vector256<ulong> g4 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a4, 0x15), Vector256.Create(3UL, 2, 2, 0));
		left.L4 = MaskedBlend2(state.Q.L4, a4 + (a4 << 1) + Vector256.Create(2 * SM2Field29.FourPMiddle) - (g4 >> 1));
		right.L4 = (g4 & Vector256.Create(SM2Field29.Mask)) + (g3 >> SM2Field29.Bits);
		Vector256<ulong> a5 = first.L5;
		Vector256<ulong> g5 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a5, 0x15), Vector256.Create(3UL, 2, 2, 0));
		left.L5 = MaskedBlend2(state.Q.L5, a5 + (a5 << 1) + Vector256.Create(2 * SM2Field29.FourPMiddle) - (g5 >> 1));
		right.L5 = (g5 & Vector256.Create(SM2Field29.Mask)) + (g4 >> SM2Field29.Bits);
		Vector256<ulong> a6 = first.L6;
		Vector256<ulong> g6 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a6, 0x15), Vector256.Create(3UL, 2, 2, 0));
		left.L6 = MaskedBlend2(state.Q.L6, a6 + (a6 << 1) + Vector256.Create(2 * SM2Field29.FourPMiddle) - (g6 >> 1));
		right.L6 = (g6 & Vector256.Create(SM2Field29.Mask)) + (g5 >> SM2Field29.Bits);
		Vector256<ulong> a7 = first.L7;
		Vector256<ulong> g7 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a7, 0x15), Vector256.Create(3UL, 2, 2, 0));
		left.L7 = MaskedBlend2(state.Q.L7, a7 + (a7 << 1) + Vector256.Create(2 * SM2Field29.FourP7) - (g7 >> 1));
		right.L7 = (g7 & Vector256.Create(SM2Field29.Mask)) + (g6 >> SM2Field29.Bits);
		Vector256<ulong> a8 = first.L8;
		Vector256<ulong> g8 = Avx2.ShiftLeftLogicalVariable(Avx2.Permute4x64(a8, 0x15), Vector256.Create(3UL, 2, 2, 0));
		left.L8 = MaskedBlend2(state.Q.L8, a8 + (a8 << 1) + Vector256.Create(2 * SM2Field29.FourP8) - (g8 >> 1));
		right.L8 = g8 + (g7 >> SM2Field29.Bits);
		SM2Field29x4Avx2.Multiply(in left, in right, out second);
		// X′ and Y′ folded and carried into xs, for the state, and the right of [α′, ·, ·, ·] carried.
		Vector256<ulong> s8 = Swap(second.L8);
		Vector256<ulong> v8 = MaskedBlend23(first.L8, second.L8) + Vector256.Create(SM2Field29.FourP8) - MaskedBlend23(second.L8, s8);
		Vector256<ulong> h = v8 >> 24;
		v8 &= Vector256.Create(SM2Field29.TopMask);
		Vector256<ulong> s0 = Swap(second.L0);
		Vector256<ulong> v0 = MaskedBlend23(first.L0, second.L0) + Vector256.Create(SM2Field29.FourP0) - MaskedBlend23(second.L0, s0) + h;
		Vector256<ulong> t0 = v0 + s0;
		xs.L0 = v0 & Vector256.Create(SM2Field29.Mask);
		left.L0 = v0 + Vector256.Create(SM2Field29.FourP0) - s0;
		Vector256<ulong> m0 = t0 + (t0 << 1);
		right.L0 = m0 & Vector256.Create(SM2Field29.Mask);
		Vector256<ulong> s1 = Swap(second.L1);
		Vector256<ulong> v1 = MaskedBlend23(first.L1, second.L1) + Vector256.Create(SM2Field29.FourP1) - MaskedBlend23(second.L1, s1);
		Vector256<ulong> t1 = v1 + s1;
		xs.L1 = (v1 & Vector256.Create(SM2Field29.Mask)) + (v0 >> SM2Field29.Bits);
		left.L1 = v1 + Vector256.Create(SM2Field29.FourP1) - s1;
		Vector256<ulong> m1 = t1 + (t1 << 1);
		right.L1 = (m1 & Vector256.Create(SM2Field29.Mask)) + (m0 >> SM2Field29.Bits);
		Vector256<ulong> s2 = Swap(second.L2);
		Vector256<ulong> v2 = MaskedBlend23(first.L2, second.L2) + Vector256.Create(SM2Field29.FourPFold2) - MaskedBlend23(second.L2, s2) - (h << 6);
		Vector256<ulong> t2 = v2 + s2;
		xs.L2 = (v2 & Vector256.Create(SM2Field29.Mask)) + (v1 >> SM2Field29.Bits);
		left.L2 = v2 + Vector256.Create(SM2Field29.FourP2) - s2;
		Vector256<ulong> m2 = t2 + (t2 << 1);
		right.L2 = (m2 & Vector256.Create(SM2Field29.Mask)) + (m1 >> SM2Field29.Bits);
		Vector256<ulong> s3 = Swap(second.L3);
		Vector256<ulong> v3 = MaskedBlend23(first.L3, second.L3) + Vector256.Create(SM2Field29.FourPFold3) - MaskedBlend23(second.L3, s3) + (h << 9);
		Vector256<ulong> t3 = v3 + s3;
		xs.L3 = (v3 & Vector256.Create(SM2Field29.Mask)) + (v2 >> SM2Field29.Bits);
		left.L3 = v3 + Vector256.Create(SM2Field29.FourP3) - s3;
		Vector256<ulong> m3 = t3 + (t3 << 1);
		right.L3 = (m3 & Vector256.Create(SM2Field29.Mask)) + (m2 >> SM2Field29.Bits);
		Vector256<ulong> s4 = Swap(second.L4);
		Vector256<ulong> v4 = MaskedBlend23(first.L4, second.L4) + Vector256.Create(SM2Field29.FourPMiddle) - MaskedBlend23(second.L4, s4);
		Vector256<ulong> t4 = v4 + s4;
		xs.L4 = (v4 & Vector256.Create(SM2Field29.Mask)) + (v3 >> SM2Field29.Bits);
		left.L4 = v4 + Vector256.Create(SM2Field29.FourPMiddle) - s4;
		Vector256<ulong> m4 = t4 + (t4 << 1);
		right.L4 = (m4 & Vector256.Create(SM2Field29.Mask)) + (m3 >> SM2Field29.Bits);
		Vector256<ulong> s5 = Swap(second.L5);
		Vector256<ulong> v5 = MaskedBlend23(first.L5, second.L5) + Vector256.Create(SM2Field29.FourPMiddle) - MaskedBlend23(second.L5, s5);
		Vector256<ulong> t5 = v5 + s5;
		xs.L5 = (v5 & Vector256.Create(SM2Field29.Mask)) + (v4 >> SM2Field29.Bits);
		left.L5 = v5 + Vector256.Create(SM2Field29.FourPMiddle) - s5;
		Vector256<ulong> m5 = t5 + (t5 << 1);
		right.L5 = (m5 & Vector256.Create(SM2Field29.Mask)) + (m4 >> SM2Field29.Bits);
		Vector256<ulong> s6 = Swap(second.L6);
		Vector256<ulong> v6 = MaskedBlend23(first.L6, second.L6) + Vector256.Create(SM2Field29.FourPMiddle) - MaskedBlend23(second.L6, s6);
		Vector256<ulong> t6 = v6 + s6;
		xs.L6 = (v6 & Vector256.Create(SM2Field29.Mask)) + (v5 >> SM2Field29.Bits);
		left.L6 = v6 + Vector256.Create(SM2Field29.FourPMiddle) - s6;
		Vector256<ulong> m6 = t6 + (t6 << 1);
		right.L6 = (m6 & Vector256.Create(SM2Field29.Mask)) + (m5 >> SM2Field29.Bits);
		Vector256<ulong> s7 = Swap(second.L7);
		Vector256<ulong> v7 = MaskedBlend23(first.L7, second.L7) + Vector256.Create(SM2Field29.FourP7) - MaskedBlend23(second.L7, s7) + (h << 21);
		Vector256<ulong> t7 = v7 + s7;
		xs.L7 = (v7 & Vector256.Create(SM2Field29.Mask)) + (v6 >> SM2Field29.Bits);
		left.L7 = v7 + Vector256.Create(SM2Field29.FourP7) - s7;
		Vector256<ulong> m7 = t7 + (t7 << 1);
		right.L7 = (m7 & Vector256.Create(SM2Field29.Mask)) + (m6 >> SM2Field29.Bits);
		Vector256<ulong> t8 = v8 + s8;
		xs.L8 = v8 + (v7 >> SM2Field29.Bits);
		left.L8 = v8 + Vector256.Create(SM2Field29.FourP8) - s8;
		Vector256<ulong> m8 = t8 + (t8 << 1);
		right.L8 = m8 + (m7 >> SM2Field29.Bits);
		SM2Field29x4Avx2.Multiply(in left, in right, out third);
		Vector256<ulong> u0 = xs.L0;
		Vector256<ulong> n0 = Broadcast0(third.L0);
		state.P.L0 = MaskedBlend3(MaskedBlend0(Avx2.Permute4x64(u0, 0xC8), n0), first.L0 << 1);
		state.Q.L0 = MaskedBlend3(MaskedBlend1(u0, second.L0), n0);
		Vector256<ulong> u1 = xs.L1;
		Vector256<ulong> n1 = Broadcast0(third.L1);
		state.P.L1 = MaskedBlend3(MaskedBlend0(Avx2.Permute4x64(u1, 0xC8), n1), first.L1 << 1);
		state.Q.L1 = MaskedBlend3(MaskedBlend1(u1, second.L1), n1);
		Vector256<ulong> u2 = xs.L2;
		Vector256<ulong> n2 = Broadcast0(third.L2);
		state.P.L2 = MaskedBlend3(MaskedBlend0(Avx2.Permute4x64(u2, 0xC8), n2), first.L2 << 1);
		state.Q.L2 = MaskedBlend3(MaskedBlend1(u2, second.L2), n2);
		Vector256<ulong> u3 = xs.L3;
		Vector256<ulong> n3 = Broadcast0(third.L3);
		state.P.L3 = MaskedBlend3(MaskedBlend0(Avx2.Permute4x64(u3, 0xC8), n3), first.L3 << 1);
		state.Q.L3 = MaskedBlend3(MaskedBlend1(u3, second.L3), n3);
		Vector256<ulong> u4 = xs.L4;
		Vector256<ulong> n4 = Broadcast0(third.L4);
		state.P.L4 = MaskedBlend3(MaskedBlend0(Avx2.Permute4x64(u4, 0xC8), n4), first.L4 << 1);
		state.Q.L4 = MaskedBlend3(MaskedBlend1(u4, second.L4), n4);
		Vector256<ulong> u5 = xs.L5;
		Vector256<ulong> n5 = Broadcast0(third.L5);
		state.P.L5 = MaskedBlend3(MaskedBlend0(Avx2.Permute4x64(u5, 0xC8), n5), first.L5 << 1);
		state.Q.L5 = MaskedBlend3(MaskedBlend1(u5, second.L5), n5);
		Vector256<ulong> u6 = xs.L6;
		Vector256<ulong> n6 = Broadcast0(third.L6);
		state.P.L6 = MaskedBlend3(MaskedBlend0(Avx2.Permute4x64(u6, 0xC8), n6), first.L6 << 1);
		state.Q.L6 = MaskedBlend3(MaskedBlend1(u6, second.L6), n6);
		Vector256<ulong> u7 = xs.L7;
		Vector256<ulong> n7 = Broadcast0(third.L7);
		state.P.L7 = MaskedBlend3(MaskedBlend0(Avx2.Permute4x64(u7, 0xC8), n7), first.L7 << 1);
		state.Q.L7 = MaskedBlend3(MaskedBlend1(u7, second.L7), n7);
		Vector256<ulong> u8 = xs.L8;
		Vector256<ulong> n8 = Broadcast0(third.L8);
		state.P.L8 = MaskedBlend3(MaskedBlend0(Avx2.Permute4x64(u8, 0xC8), n8), first.L8 << 1);
		state.Q.L8 = MaskedBlend3(MaskedBlend1(u8, second.L8), n8);
	}


	// The entry (x, y, 1) of an affine point of the form E of SM2Field52, reduced: each coordinate a·2^260 as a·2^261, its limbs of radix 2^52 doubled and cut into limbs of radix 2^29, limbs 2m + 1 taking the bits of a limb of radix 2^52 that cross into the next as a sum, below 2^30, for Reduce.
	[SkipLocalsInit]
	internal static void ToEntry(in AffinePoint<SM2Field52> point, out SM2QuadEntry entry)
	{
		Unsafe.SkipInit(out entry);
		Vector256<ulong> mask = Vector256.Create(SM2Field29.Mask);
		ref ulong x = ref Unsafe.As<SM2Field52, ulong>(ref Unsafe.AsRef(in point.X));
		ref ulong y = ref Unsafe.As<SM2Field52, ulong>(ref Unsafe.AsRef(in point.Y));
		Vector256<ulong> d0 = Vector256.Create(0, Unsafe.Add(ref x, 0), Unsafe.Add(ref y, 0), 0) << 1;
		Vector256<ulong> d1 = Vector256.Create(0, Unsafe.Add(ref x, 1), Unsafe.Add(ref y, 1), 0) << 1;
		Vector256<ulong> d2 = Vector256.Create(0, Unsafe.Add(ref x, 2), Unsafe.Add(ref y, 2), 0) << 1;
		Vector256<ulong> d3 = Vector256.Create(0, Unsafe.Add(ref x, 3), Unsafe.Add(ref y, 3), 0) << 1;
		Vector256<ulong> d4 = Vector256.Create(0, Unsafe.Add(ref x, 4), Unsafe.Add(ref y, 4), 0) << 1;
		entry.EA.L0 = d0 & mask;
		entry.EA.L1 = (d0 >> 29) + (d1 << 23 & mask);
		entry.EA.L2 = d1 >> 6 & mask;
		entry.EA.L3 = (d1 >> 35) + (d2 << 17 & mask);
		entry.EA.L4 = d2 >> 12 & mask;
		entry.EA.L5 = (d2 >> 41) + (d3 << 11 & mask);
		entry.EA.L6 = d3 >> 18 & mask;
		entry.EA.L7 = (d3 >> 47) + (d4 << 5 & mask);
		entry.EA.L8 = d4 >> 24;
		SM2Field29x4Avx2.Reduce(in entry.EA, out entry.EA);
		SM2Field29x4Avx2.One(out entry.EB);
		Vector256<ulong> o0 = entry.EB.L0;
		Vector256<ulong> a0 = Blend0(Blend3(entry.EA.L0, o0), o0);
		entry.EA.L0 = a0;
		entry.EB.L0 = Blend0(o0, Broadcast1(a0));
		Vector256<ulong> o1 = entry.EB.L1;
		Vector256<ulong> a1 = Blend0(Blend3(entry.EA.L1, o1), o1);
		entry.EA.L1 = a1;
		entry.EB.L1 = Blend0(o1, Broadcast1(a1));
		Vector256<ulong> o2 = entry.EB.L2;
		Vector256<ulong> a2 = Blend0(Blend3(entry.EA.L2, o2), o2);
		entry.EA.L2 = a2;
		entry.EB.L2 = Blend0(o2, Broadcast1(a2));
		Vector256<ulong> o3 = entry.EB.L3;
		Vector256<ulong> a3 = Blend0(Blend3(entry.EA.L3, o3), o3);
		entry.EA.L3 = a3;
		entry.EB.L3 = Blend0(o3, Broadcast1(a3));
		Vector256<ulong> o4 = entry.EB.L4;
		Vector256<ulong> a4 = Blend0(Blend3(entry.EA.L4, o4), o4);
		entry.EA.L4 = a4;
		entry.EB.L4 = Blend0(o4, Broadcast1(a4));
		Vector256<ulong> o5 = entry.EB.L5;
		Vector256<ulong> a5 = Blend0(Blend3(entry.EA.L5, o5), o5);
		entry.EA.L5 = a5;
		entry.EB.L5 = Blend0(o5, Broadcast1(a5));
		Vector256<ulong> o6 = entry.EB.L6;
		Vector256<ulong> a6 = Blend0(Blend3(entry.EA.L6, o6), o6);
		entry.EA.L6 = a6;
		entry.EB.L6 = Blend0(o6, Broadcast1(a6));
		Vector256<ulong> o7 = entry.EB.L7;
		Vector256<ulong> a7 = Blend0(Blend3(entry.EA.L7, o7), o7);
		entry.EA.L7 = a7;
		entry.EB.L7 = Blend0(o7, Broadcast1(a7));
		Vector256<ulong> o8 = entry.EB.L8;
		Vector256<ulong> a8 = Blend0(Blend3(entry.EA.L8, o8), o8);
		entry.EA.L8 = a8;
		entry.EB.L8 = Blend0(o8, Broadcast1(a8));
	}

	// The point of an entry in the form E of SM2Field52, through Halve and Reduce.
	private static void ToJacobian(in SM2QuadEntry entry, out JacobianPoint<SM2Field52> result)
	{
		SM2Field29x4Avx2.Halve(in entry.EA, out SM2Field29x4Avx2 a);
		SM2Field29x4Avx2.Reduce(in a, out a);
		Lane(in a, 1, out result.X);
		Lane(in a, 2, out result.Y);
		Lane(in a, 3, out result.Z);
	}

	// Lane of a value that Reduce left, in the form E of SM2Field52, as SM2Field29.ToField52 joins its limbs.
	private static void Lane(in SM2Field29x4Avx2 value, int lane, out SM2Field52 result)
	{
		SM2Field29.ToField52(in Unsafe.Add(ref Unsafe.As<SM2Field29x4Avx2, ulong>(ref Unsafe.AsRef(in value)), lane), LaneCount, out result);
	}

	// Lane 0 of b, the others of a.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> Blend0(Vector256<ulong> a, Vector256<ulong> b)
	{
		return Avx2.Blend(a.AsUInt32(), b.AsUInt32(), 0x03).AsUInt64();
	}

	// Lane 1 of b, the others of a.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> Blend1(Vector256<ulong> a, Vector256<ulong> b)
	{
		return Avx2.Blend(a.AsUInt32(), b.AsUInt32(), 0x0C).AsUInt64();
	}

	// Lane 2 of b, the others of a.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> Blend2(Vector256<ulong> a, Vector256<ulong> b)
	{
		return Avx2.Blend(a.AsUInt32(), b.AsUInt32(), 0x30).AsUInt64();
	}

	// Lane 3 of b, the others of a.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> Blend3(Vector256<ulong> a, Vector256<ulong> b)
	{
		return Avx2.Blend(a.AsUInt32(), b.AsUInt32(), 0xC0).AsUInt64();
	}

	// Lanes 2 and 3 of b, the others of a.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> Blend23(Vector256<ulong> a, Vector256<ulong> b)
	{
		return Avx2.Blend(a.AsUInt32(), b.AsUInt32(), 0xF0).AsUInt64();
	}

	// Lane 0 of b, the others of a, as Blend0, but under a mask register where AVX-512 has one, which lets the JIT merge the blend into the operation that computes b. DoubleTwice and DoubleOnce take these; the larger formulas take the plain ones, whose smaller bodies keep them within the inlining budget of the JIT.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> MaskedBlend0(Vector256<ulong> a, Vector256<ulong> b)
	{
		return Avx512F.VL.IsSupported ? Avx512F.VL.BlendVariable(a, b, Vector256.Create(ulong.MaxValue, 0, 0, 0)) : Blend0(a, b);
	}

	// Lane 1 of b, the others of a, as MaskedBlend0.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> MaskedBlend1(Vector256<ulong> a, Vector256<ulong> b)
	{
		return Avx512F.VL.IsSupported ? Avx512F.VL.BlendVariable(a, b, Vector256.Create(0, ulong.MaxValue, 0, 0)) : Blend1(a, b);
	}

	// Lane 2 of b, the others of a, as MaskedBlend0.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> MaskedBlend2(Vector256<ulong> a, Vector256<ulong> b)
	{
		return Avx512F.VL.IsSupported ? Avx512F.VL.BlendVariable(a, b, Vector256.Create(0, 0, ulong.MaxValue, 0)) : Blend2(a, b);
	}

	// Lane 3 of b, the others of a, as MaskedBlend0.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> MaskedBlend3(Vector256<ulong> a, Vector256<ulong> b)
	{
		return Avx512F.VL.IsSupported ? Avx512F.VL.BlendVariable(a, b, Vector256.Create(0, 0, 0, ulong.MaxValue)) : Blend3(a, b);
	}

	// Lanes 2 and 3 of b, the others of a, as MaskedBlend0.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> MaskedBlend23(Vector256<ulong> a, Vector256<ulong> b)
	{
		return Avx512F.VL.IsSupported ? Avx512F.VL.BlendVariable(a, b, Vector256.Create(0, 0, ulong.MaxValue, ulong.MaxValue)) : Blend23(a, b);
	}

	// Lane 0 in every lane.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> Broadcast0(Vector256<ulong> a)
	{
		return Avx2.Permute4x64(a, 0x00);
	}

	// The two lanes of each half swapped.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> Swap(Vector256<ulong> a)
	{
		return Avx2.Shuffle(a.AsUInt32(), 0x4E).AsUInt64();
	}

	// Lane 1 in every lane.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> Broadcast1(Vector256<ulong> a)
	{
		return Avx2.Permute4x64(a, 0x55);
	}

	// Lane 3 in every lane.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<ulong> Broadcast3(Vector256<ulong> a)
	{
		return Avx2.Permute4x64(a, 0xFF);
	}
}

// A point of SM2QuadFormulas: P = [α, Y, X, Z] and Q = [X, δ, ·, α] for δ = Z² and α = 3(X − δ)(X + δ).
internal struct SM2QuadState
{
	internal SM2Field29x4Avx2 P;
	internal SM2Field29x4Avx2 Q;

	// mask is a lane mask; result may be either input.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void ConditionalSelect(ref readonly ulong mask, in SM2QuadState whenSet, in SM2QuadState whenClear, out SM2QuadState result)
	{
		SM2Field29x4Avx2.ConditionalSelect(in mask, in whenSet.P, in whenClear.P, out result.P);
		SM2Field29x4Avx2.ConditionalSelect(in mask, in whenSet.Q, in whenClear.Q, out result.Q);
	}
}

// An entry of SM2QuadFormulas: EA = [Z², X, Y, Z] and EB = [X, Z², Z³, Z³].
internal struct SM2QuadEntry
{
	internal SM2Field29x4Avx2 EA;
	internal SM2Field29x4Avx2 EB;
}
