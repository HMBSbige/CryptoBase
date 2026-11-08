using CryptoBase.EllipticCurves;
using CryptoBase.Kdf;
using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.Signatures;

// The order n of the group of a signature scheme whose nonces SM3Nonce draws. n − 1 lies in (2^255, 2^256), so its reciprocal ⌊2^512/(n − 1)⌋ lies in (2^256, 2^257).
internal interface ISM3NonceOrder : IMontgomeryModulus
{
	// The tag of the scheme, which keeps its nonces apart from those of the others: at most 19 bytes, so that Z ‖ ct fits two blocks with 32 bytes of additional data.
	static abstract ReadOnlySpan<byte> NonceTag { get; }

	// ⌊2^512/(n − 1)⌋ − 2^256.
	static abstract ReadOnlySpan<ulong> NonceReciprocal { get; }
}

// The hedged nonces of SM2 and SM9 signatures. Candidate c is v = SM3(Z ‖ ct) ‖ SM3(Z ‖ ct + 1) for ct = 2c + 1, blocks 2c + 1 and 2c + 2 of the KDF of GB/T 32918.4-2016, Sec. 5.4.3, over Z = tag ‖ key ‖ hash ‖ additional data, and the nonce is (v mod (n − 1)) + 1 for v as a 512-bit big-endian integer, as FIPS 186-5, A.2.1, draws a scalar from extra bits: it lies in [1, n − 1], within n/2^512 < 2^−256 of uniform there. All of Z but the additional data has a fixed length, as has ct, so Z ‖ ct parses one way.
// The state absorbs Z once, and each block finishes a copy of it: with a tag of 19 bytes and 32 bytes of additional data, Z ‖ ct is 119 bytes, so the first block of Z is compressed once for all candidates and each block of v takes one compression, three for a nonce. With empty additional data the nonces follow from the key and the hash alone.
// The state and the candidates are as secret as the key: nothing branches on or indexes by them but the retries of the schemes, the copies are erased, and Clear erases the state. Keep a nonce in one writable location and do not copy it.
internal struct SM3Nonce<TOrder> where TOrder : unmanaged, ISM3NonceOrder
{
	private const int ValueLength = 2 * SM3KdfState.BlockLength;

	private SM3KdfState _seed;
	// ct of the next candidate.
	private uint _counter;

	// key and hash are ByteLength bytes each. Not inlined, so that the appends stay out of the frames of the signatures.
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal void Initialize(ReadOnlySpan<byte> key, ReadOnlySpan<byte> hash, ReadOnlySpan<byte> additionalData)
	{
		Debug.Assert(key.Length == TOrder.ByteLength && hash.Length == TOrder.ByteLength);

		_seed.Initialize();
		_seed.Append(TOrder.NonceTag);
		_seed.Append(key);
		_seed.Append(hash);
		_seed.Append(additionalData);
		_counter = 1;
	}

	// The candidate for the first attempt of a signature, then one for each attempt after one that the scheme rejects.
	[SkipLocalsInit]
	internal void Next(out FieldElement<TOrder> result)
	{
		using CryptoBuffer<byte> value = new(stackalloc byte[ValueLength]);
		_seed.WriteBlock(_counter, value.Span);
		_seed.WriteBlock(_counter + 1, value.Span.Slice(SM3KdfState.BlockLength));
		_counter += 2;
		Reduce(value.Span, out result);
	}

	internal void Clear()
	{
		_seed.Clear();
		_counter = 0;
	}

	// (v mod M) + 1 for M = n − 1 and v of 64 big-endian bytes, by the reduction of Barrett, HAC 14.42 with b = 2^64 and k = 4. For μ = ⌊2^512/M⌋ = 2^256 + NonceReciprocal, q1 = ⌊v/2^192⌋ and q3 = ⌊q1·μ/2^320⌋, v/M − q1·μ/2^320 = (v mod 2^192)/M + q1·δ/2^320 < 2^−63 + δ for δ = 2^512/M − μ, so q3 lies in [q − 1, q] for q = ⌊v/M⌋ while δ < 1 − 2^−63, as it is for both orders, 0.12 for SM2 and 0.72 for SM9. v − q3·M then lies in [0, 2M), which its five low limbs hold, and one subtraction of M where it does not borrow leaves v mod M. The low limbs of v are read where the subtraction takes them. Neither the time nor the addresses depend on v.
	[SkipLocalsInit]
	internal static void Reduce(ReadOnlySpan<byte> value, out FieldElement<TOrder> result)
	{
		Debug.Assert(value.Length is ValueLength && TOrder.LimbCount is 4);

		ref byte input = ref MemoryMarshal.GetReference(value);
		ReadOnlySpan<ulong> modulus = TOrder.Modulus;
		ReadOnlySpan<ulong> reciprocal = TOrder.NonceReciprocal;
		// n is odd, so M differs from n in limb 0 alone.
		ulong m0 = modulus[0] - 1;
		ulong m1 = modulus[1];
		ulong m2 = modulus[2];
		ulong m3 = modulus[3];
		ulong u0 = reciprocal[0];
		ulong u1 = reciprocal[1];
		ulong u2 = reciprocal[2];
		ulong u3 = reciprocal[3];
		ulong x3 = Limb(ref input, 3);
		ulong x4 = Limb(ref input, 4);
		ulong x5 = Limb(ref input, 5);
		ulong x6 = Limb(ref input, 6);
		ulong x7 = Limb(ref input, 7);

		// q1 = (x3, …, x7) times NonceReciprocal, row by row: limbs 0 to 3 carry nothing into the others but through the high limbs of the products, so only limbs 4 to 8 are kept.
		ulong high = Multiply(x3, u0, out _);
		high = MultiplyAdd(x4, u0, high, 0, out ulong t1);
		high = MultiplyAdd(x5, u0, high, 0, out ulong t2);
		high = MultiplyAdd(x6, u0, high, 0, out ulong t3);
		ulong t5 = MultiplyAdd(x7, u0, high, 0, out ulong t4);
		high = MultiplyAdd(x3, u1, t1, 0, out _);
		high = MultiplyAdd(x4, u1, t2, high, out t2);
		high = MultiplyAdd(x5, u1, t3, high, out t3);
		high = MultiplyAdd(x6, u1, t4, high, out t4);
		ulong t6 = MultiplyAdd(x7, u1, t5, high, out t5);
		high = MultiplyAdd(x3, u2, t2, 0, out _);
		high = MultiplyAdd(x4, u2, t3, high, out t3);
		high = MultiplyAdd(x5, u2, t4, high, out t4);
		high = MultiplyAdd(x6, u2, t5, high, out t5);
		ulong t7 = MultiplyAdd(x7, u2, t6, high, out t6);
		high = MultiplyAdd(x3, u3, t3, 0, out _);
		high = MultiplyAdd(x4, u3, t4, high, out t4);
		high = MultiplyAdd(x5, u3, t5, high, out t5);
		high = MultiplyAdd(x6, u3, t6, high, out t6);
		ulong t8 = MultiplyAdd(x7, u3, t7, high, out t7);
		// The 2^256 of μ adds q1 from limb 4 on; the product is below 2^577, so q3 = (t5, …, t9) has t9 of 0 or 1.
		ulong carry = 0;
		_ = AddWithCarry(t4, x3, ref carry);
		t5 = AddWithCarry(t5, x4, ref carry);
		t6 = AddWithCarry(t6, x5, ref carry);
		t7 = AddWithCarry(t7, x6, ref carry);
		t8 = AddWithCarry(t8, x7, ref carry);
		ulong t9 = carry;

		// q3·M mod 2^320, whose limb 4 takes the low limbs of the products that reach it.
		high = Multiply(t5, m0, out ulong p0);
		high = MultiplyAdd(t5, m1, high, 0, out ulong p1);
		high = MultiplyAdd(t5, m2, high, 0, out ulong p2);
		ulong p4 = MultiplyAdd(t5, m3, high, 0, out ulong p3);
		high = MultiplyAdd(t6, m0, p1, 0, out p1);
		high = MultiplyAdd(t6, m1, p2, high, out p2);
		high = MultiplyAdd(t6, m2, p3, high, out p3);
		p4 += t6 * m3 + high;
		high = MultiplyAdd(t7, m0, p2, 0, out p2);
		high = MultiplyAdd(t7, m1, p3, high, out p3);
		p4 += t7 * m2 + high;
		high = MultiplyAdd(t8, m0, p3, 0, out p3);
		p4 += t8 * m1 + high + (m0 & 0 - t9);

		ulong borrow = 0;
		ulong r0 = SubtractWithBorrow(Limb(ref input, 0), p0, ref borrow);
		ulong r1 = SubtractWithBorrow(Limb(ref input, 1), p1, ref borrow);
		ulong r2 = SubtractWithBorrow(Limb(ref input, 2), p2, ref borrow);
		ulong r3 = SubtractWithBorrow(Limb(ref input, 3), p3, ref borrow);
		ulong r4 = Limb(ref input, 4) - p4 - borrow;
		borrow = 0;
		ulong d0 = SubtractWithBorrow(r0, m0, ref borrow);
		ulong d1 = SubtractWithBorrow(r1, m1, ref borrow);
		ulong d2 = SubtractWithBorrow(r2, m2, ref borrow);
		ulong d3 = SubtractWithBorrow(r3, m3, ref borrow);
		_ = SubtractWithBorrow(r4, 0, ref borrow);
		// All ones where r is at least M.
		ulong keep = borrow - 1;
		Debug.Assert((r4 & ~keep) is 0);

		// (r mod M) + 1 is at most M < 2^256, so it does not carry out.
		Unsafe.SkipInit(out result);
		Span<ulong> limbs = MemoryMarshal.Cast<FieldElement<TOrder>, ulong>(new Span<FieldElement<TOrder>>(ref result));
		carry = 1;
		limbs[0] = AddWithCarry(Select(keep, d0, r0), 0, ref carry);
		limbs[1] = AddWithCarry(Select(keep, d1, r1), 0, ref carry);
		limbs[2] = AddWithCarry(Select(keep, d2, r2), 0, ref carry);
		limbs[3] = AddWithCarry(Select(keep, d3, r3), 0, ref carry);
	}

	// Limb i, least significant first, of the 64 big-endian bytes at input.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ulong Limb(ref byte input, int i)
	{
		return BinaryPrimitives.ReverseEndianness(Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref input, ValueLength - sizeof(ulong) * (i + 1))));
	}
}
