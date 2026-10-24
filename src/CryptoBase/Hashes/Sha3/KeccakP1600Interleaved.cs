namespace CryptoBase.Hashes.Sha3;

// The round of KeccakP1600.PermuteScalar, in the same plane order, applied lane-wise to vectors of interleaved states. The rounds are spelled out in this method rather than in an inlined helper because the inliner only budgets enough for the hundreds of small lane operations when the method they are inlined into is this large itself.
internal static class KeccakP1600Interleaved
{
	// Unlike the scalar round, the column parities are recomputed from the state rather than accumulated across the planes, which keeps five fewer vectors live through χ. The rotation counts are the ρ offsets of KeccakP1600Constants.RhoOffsets, written out because the rotate instructions take them as immediates.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void Permute<TVector, TLanes>(ref TVector state) where TVector : struct where TLanes : IKeccakP1600Lanes<TVector>
	{
		TVector a0 = state;
		TVector a1 = Unsafe.Add(ref state, 1);
		TVector a2 = Unsafe.Add(ref state, 2);
		TVector a3 = Unsafe.Add(ref state, 3);
		TVector a4 = Unsafe.Add(ref state, 4);
		TVector a5 = Unsafe.Add(ref state, 5);
		TVector a6 = Unsafe.Add(ref state, 6);
		TVector a7 = Unsafe.Add(ref state, 7);
		TVector a8 = Unsafe.Add(ref state, 8);
		TVector a9 = Unsafe.Add(ref state, 9);
		TVector a10 = Unsafe.Add(ref state, 10);
		TVector a11 = Unsafe.Add(ref state, 11);
		TVector a12 = Unsafe.Add(ref state, 12);
		TVector a13 = Unsafe.Add(ref state, 13);
		TVector a14 = Unsafe.Add(ref state, 14);
		TVector a15 = Unsafe.Add(ref state, 15);
		TVector a16 = Unsafe.Add(ref state, 16);
		TVector a17 = Unsafe.Add(ref state, 17);
		TVector a18 = Unsafe.Add(ref state, 18);
		TVector a19 = Unsafe.Add(ref state, 19);
		TVector a20 = Unsafe.Add(ref state, 20);
		TVector a21 = Unsafe.Add(ref state, 21);
		TVector a22 = Unsafe.Add(ref state, 22);
		TVector a23 = Unsafe.Add(ref state, 23);
		TVector a24 = Unsafe.Add(ref state, 24);
		TVector e0, e1, e2, e3, e4, e5, e6, e7, e8, e9, e10, e11, e12, e13, e14, e15, e16, e17, e18, e19, e20, e21, e22, e23, e24;
		TVector c0, c1, c2, c3, c4, d0, d1, d2, d3, d4, b0, b1, b2, b3, b4;
		ref ulong roundConstants = ref MemoryMarshal.GetReference(KeccakP1600Constants.RoundConstants);

		for (int round = 0; round < KeccakP1600Constants.Rounds; round += 2)
		{
			c0 = TLanes.Xor5(a0, a5, a10, a15, a20);
			c1 = TLanes.Xor5(a1, a6, a11, a16, a21);
			c2 = TLanes.Xor5(a2, a7, a12, a17, a22);
			c3 = TLanes.Xor5(a3, a8, a13, a18, a23);
			c4 = TLanes.Xor5(a4, a9, a14, a19, a24);
			d0 = TLanes.Xor(c4, TLanes.RotateLeft(c1, 1));
			d1 = TLanes.Xor(c0, TLanes.RotateLeft(c2, 1));
			d2 = TLanes.Xor(c1, TLanes.RotateLeft(c3, 1));
			d3 = TLanes.Xor(c2, TLanes.RotateLeft(c4, 1));
			d4 = TLanes.Xor(c3, TLanes.RotateLeft(c0, 1));

			b0 = TLanes.Xor(a0, d0);
			b1 = TLanes.RotateLeft(TLanes.Xor(a6, d1), 44);
			b2 = TLanes.RotateLeft(TLanes.Xor(a12, d2), 43);
			b3 = TLanes.RotateLeft(TLanes.Xor(a18, d3), 21);
			b4 = TLanes.RotateLeft(TLanes.Xor(a24, d4), 14);
			e0 = TLanes.Xor(TLanes.XorAndNot(b0, b1, b2), TLanes.Create(Unsafe.Add(ref roundConstants, round)));
			e1 = TLanes.XorAndNot(b1, b2, b3);
			e2 = TLanes.XorAndNot(b2, b3, b4);
			e3 = TLanes.XorAndNot(b3, b4, b0);
			e4 = TLanes.XorAndNot(b4, b0, b1);

			b0 = TLanes.RotateLeft(TLanes.Xor(a3, d3), 28);
			b1 = TLanes.RotateLeft(TLanes.Xor(a9, d4), 20);
			b2 = TLanes.RotateLeft(TLanes.Xor(a10, d0), 3);
			b3 = TLanes.RotateLeft(TLanes.Xor(a16, d1), 45);
			b4 = TLanes.RotateLeft(TLanes.Xor(a22, d2), 61);
			e5 = TLanes.XorAndNot(b0, b1, b2);
			e6 = TLanes.XorAndNot(b1, b2, b3);
			e7 = TLanes.XorAndNot(b2, b3, b4);
			e8 = TLanes.XorAndNot(b3, b4, b0);
			e9 = TLanes.XorAndNot(b4, b0, b1);

			b0 = TLanes.RotateLeft(TLanes.Xor(a1, d1), 1);
			b1 = TLanes.RotateLeft(TLanes.Xor(a7, d2), 6);
			b2 = TLanes.RotateLeft(TLanes.Xor(a13, d3), 25);
			b3 = TLanes.RotateLeft(TLanes.Xor(a19, d4), 8);
			b4 = TLanes.RotateLeft(TLanes.Xor(a20, d0), 18);
			e10 = TLanes.XorAndNot(b0, b1, b2);
			e11 = TLanes.XorAndNot(b1, b2, b3);
			e12 = TLanes.XorAndNot(b2, b3, b4);
			e13 = TLanes.XorAndNot(b3, b4, b0);
			e14 = TLanes.XorAndNot(b4, b0, b1);

			b0 = TLanes.RotateLeft(TLanes.Xor(a4, d4), 27);
			b1 = TLanes.RotateLeft(TLanes.Xor(a5, d0), 36);
			b2 = TLanes.RotateLeft(TLanes.Xor(a11, d1), 10);
			b3 = TLanes.RotateLeft(TLanes.Xor(a17, d2), 15);
			b4 = TLanes.RotateLeft(TLanes.Xor(a23, d3), 56);
			e15 = TLanes.XorAndNot(b0, b1, b2);
			e16 = TLanes.XorAndNot(b1, b2, b3);
			e17 = TLanes.XorAndNot(b2, b3, b4);
			e18 = TLanes.XorAndNot(b3, b4, b0);
			e19 = TLanes.XorAndNot(b4, b0, b1);

			b0 = TLanes.RotateLeft(TLanes.Xor(a2, d2), 62);
			b1 = TLanes.RotateLeft(TLanes.Xor(a8, d3), 55);
			b2 = TLanes.RotateLeft(TLanes.Xor(a14, d4), 39);
			b3 = TLanes.RotateLeft(TLanes.Xor(a15, d0), 41);
			b4 = TLanes.RotateLeft(TLanes.Xor(a21, d1), 2);
			e20 = TLanes.XorAndNot(b0, b1, b2);
			e21 = TLanes.XorAndNot(b1, b2, b3);
			e22 = TLanes.XorAndNot(b2, b3, b4);
			e23 = TLanes.XorAndNot(b3, b4, b0);
			e24 = TLanes.XorAndNot(b4, b0, b1);

			c0 = TLanes.Xor5(e0, e5, e10, e15, e20);
			c1 = TLanes.Xor5(e1, e6, e11, e16, e21);
			c2 = TLanes.Xor5(e2, e7, e12, e17, e22);
			c3 = TLanes.Xor5(e3, e8, e13, e18, e23);
			c4 = TLanes.Xor5(e4, e9, e14, e19, e24);
			d0 = TLanes.Xor(c4, TLanes.RotateLeft(c1, 1));
			d1 = TLanes.Xor(c0, TLanes.RotateLeft(c2, 1));
			d2 = TLanes.Xor(c1, TLanes.RotateLeft(c3, 1));
			d3 = TLanes.Xor(c2, TLanes.RotateLeft(c4, 1));
			d4 = TLanes.Xor(c3, TLanes.RotateLeft(c0, 1));

			b0 = TLanes.Xor(e0, d0);
			b1 = TLanes.RotateLeft(TLanes.Xor(e6, d1), 44);
			b2 = TLanes.RotateLeft(TLanes.Xor(e12, d2), 43);
			b3 = TLanes.RotateLeft(TLanes.Xor(e18, d3), 21);
			b4 = TLanes.RotateLeft(TLanes.Xor(e24, d4), 14);
			a0 = TLanes.Xor(TLanes.XorAndNot(b0, b1, b2), TLanes.Create(Unsafe.Add(ref roundConstants, round + 1)));
			a1 = TLanes.XorAndNot(b1, b2, b3);
			a2 = TLanes.XorAndNot(b2, b3, b4);
			a3 = TLanes.XorAndNot(b3, b4, b0);
			a4 = TLanes.XorAndNot(b4, b0, b1);

			b0 = TLanes.RotateLeft(TLanes.Xor(e3, d3), 28);
			b1 = TLanes.RotateLeft(TLanes.Xor(e9, d4), 20);
			b2 = TLanes.RotateLeft(TLanes.Xor(e10, d0), 3);
			b3 = TLanes.RotateLeft(TLanes.Xor(e16, d1), 45);
			b4 = TLanes.RotateLeft(TLanes.Xor(e22, d2), 61);
			a5 = TLanes.XorAndNot(b0, b1, b2);
			a6 = TLanes.XorAndNot(b1, b2, b3);
			a7 = TLanes.XorAndNot(b2, b3, b4);
			a8 = TLanes.XorAndNot(b3, b4, b0);
			a9 = TLanes.XorAndNot(b4, b0, b1);

			b0 = TLanes.RotateLeft(TLanes.Xor(e1, d1), 1);
			b1 = TLanes.RotateLeft(TLanes.Xor(e7, d2), 6);
			b2 = TLanes.RotateLeft(TLanes.Xor(e13, d3), 25);
			b3 = TLanes.RotateLeft(TLanes.Xor(e19, d4), 8);
			b4 = TLanes.RotateLeft(TLanes.Xor(e20, d0), 18);
			a10 = TLanes.XorAndNot(b0, b1, b2);
			a11 = TLanes.XorAndNot(b1, b2, b3);
			a12 = TLanes.XorAndNot(b2, b3, b4);
			a13 = TLanes.XorAndNot(b3, b4, b0);
			a14 = TLanes.XorAndNot(b4, b0, b1);

			b0 = TLanes.RotateLeft(TLanes.Xor(e4, d4), 27);
			b1 = TLanes.RotateLeft(TLanes.Xor(e5, d0), 36);
			b2 = TLanes.RotateLeft(TLanes.Xor(e11, d1), 10);
			b3 = TLanes.RotateLeft(TLanes.Xor(e17, d2), 15);
			b4 = TLanes.RotateLeft(TLanes.Xor(e23, d3), 56);
			a15 = TLanes.XorAndNot(b0, b1, b2);
			a16 = TLanes.XorAndNot(b1, b2, b3);
			a17 = TLanes.XorAndNot(b2, b3, b4);
			a18 = TLanes.XorAndNot(b3, b4, b0);
			a19 = TLanes.XorAndNot(b4, b0, b1);

			b0 = TLanes.RotateLeft(TLanes.Xor(e2, d2), 62);
			b1 = TLanes.RotateLeft(TLanes.Xor(e8, d3), 55);
			b2 = TLanes.RotateLeft(TLanes.Xor(e14, d4), 39);
			b3 = TLanes.RotateLeft(TLanes.Xor(e15, d0), 41);
			b4 = TLanes.RotateLeft(TLanes.Xor(e21, d1), 2);
			a20 = TLanes.XorAndNot(b0, b1, b2);
			a21 = TLanes.XorAndNot(b1, b2, b3);
			a22 = TLanes.XorAndNot(b2, b3, b4);
			a23 = TLanes.XorAndNot(b3, b4, b0);
			a24 = TLanes.XorAndNot(b4, b0, b1);
		}

		state = a0;
		Unsafe.Add(ref state, 1) = a1;
		Unsafe.Add(ref state, 2) = a2;
		Unsafe.Add(ref state, 3) = a3;
		Unsafe.Add(ref state, 4) = a4;
		Unsafe.Add(ref state, 5) = a5;
		Unsafe.Add(ref state, 6) = a6;
		Unsafe.Add(ref state, 7) = a7;
		Unsafe.Add(ref state, 8) = a8;
		Unsafe.Add(ref state, 9) = a9;
		Unsafe.Add(ref state, 10) = a10;
		Unsafe.Add(ref state, 11) = a11;
		Unsafe.Add(ref state, 12) = a12;
		Unsafe.Add(ref state, 13) = a13;
		Unsafe.Add(ref state, 14) = a14;
		Unsafe.Add(ref state, 15) = a15;
		Unsafe.Add(ref state, 16) = a16;
		Unsafe.Add(ref state, 17) = a17;
		Unsafe.Add(ref state, 18) = a18;
		Unsafe.Add(ref state, 19) = a19;
		Unsafe.Add(ref state, 20) = a20;
		Unsafe.Add(ref state, 21) = a21;
		Unsafe.Add(ref state, 22) = a22;
		Unsafe.Add(ref state, 23) = a23;
		Unsafe.Add(ref state, 24) = a24;
	}
}
