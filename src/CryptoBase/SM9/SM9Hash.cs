using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.SM9;
using CryptoBase.Kdf;
using static CryptoBase.EllipticCurves.LimbArithmetic;

namespace CryptoBase.SM9;

// H1 and H2 of GM/T 0044.2-2016, Sec. 5.4.2 (and 0044.3 and 0044.4), with SM3 and n = N: hlen = 8·⌈5·log2(N)/32⌉ = 320 bits, so Ha = SM3(prefix ‖ Z ‖ 00000001) ‖ the leftmost 64 bits of SM3(prefix ‖ Z ‖ 00000002), and h = (Ha mod (N − 1)) + 1 in [1, N − 1], with the prefix 0x01 for H1 and 0x02 for H2. Ha is the KDF of GM/T 0044.3, Sec. 5.4.3, over prefix ‖ Z, cut to 40 bytes, so an SM3KdfState absorbs prefix ‖ Z.
internal static class SM9Hash
{
	private const int HashLength = 40;

	// The limbs of M = N − 1, least significant first.
	private const ulong M0 = 0xE56EE19CD69ECF24;
	private const ulong M1 = 0x49F2934B18EA8BEE;
	private const ulong M2 = 0xD603AB4FF58EC744;
	private const ulong M3 = 0xB640000002A3A6F1;

	// μ = ⌊2^320/M⌋ = 2^64 + MuLow, as M lies in (2^255, 2^256).
	private const ulong MuLow = 0x67980E0BEB5759A6;

	// H1(ID ‖ hid, N), plain. The ID is public.
	[SkipLocalsInit]
	internal static void H1(ReadOnlySpan<byte> id, byte hid, out FieldElement<SM9Order> result)
	{
		Unsafe.SkipInit(out SM3KdfState kdf);
		kdf.Initialize();
		kdf.Append([0x01]);
		kdf.Append(id);
		kdf.Append(new ReadOnlySpan<byte>(in hid));
		Finish(in kdf, out result);
		kdf.Clear();
	}

	// Absorbs 0x02 ‖ M, the part of H2(M ‖ w, N) before w.
	internal static void StartH2(ReadOnlySpan<byte> message, out SM3KdfState state)
	{
		Unsafe.SkipInit(out state);
		state.Initialize();
		state.Append([0x02]);
		state.Append(message);
	}

	// h from a state that has absorbed prefix ‖ Z. Ha may be secret, as it is in signing.
	[SkipLocalsInit]
	internal static void Finish(in SM3KdfState state, out FieldElement<SM9Order> result)
	{
		using CryptoBuffer<byte> hash = new(stackalloc byte[HashLength]);
		state.Derive(hash.Span);
		Reduce(hash.Span, out result);
	}

	// (Ha mod M) + 1 for Ha of 40 big-endian bytes, by Barrett reduction: with Ha = x4·2^256 + L, q̂ = ⌊x4·μ/2^64⌋ = x4 + ⌊x4·MuLow/2^64⌋, of up to 65 bits, is at most q = ⌊Ha/M⌋, and as Ha/M − x4·μ/2^64 < L/M + x4·(2^320/M − μ)/2^64 < 1.75, at least q − 2. So Ha − q̂·M lies in [0, 3M), and two subtractions of M where they do not borrow leave Ha mod M, below 2^256. Neither the time nor the addresses depend on Ha.
	[SkipLocalsInit]
	internal static void Reduce(ReadOnlySpan<byte> hash, out FieldElement<SM9Order> result)
	{
		Debug.Assert(hash.Length is HashLength);

		ulong x4 = BinaryPrimitives.ReadUInt64BigEndian(hash);
		ulong x3 = BinaryPrimitives.ReadUInt64BigEndian(hash.Slice(8));
		ulong x2 = BinaryPrimitives.ReadUInt64BigEndian(hash.Slice(16));
		ulong x1 = BinaryPrimitives.ReadUInt64BigEndian(hash.Slice(24));
		ulong x0 = BinaryPrimitives.ReadUInt64BigEndian(hash.Slice(32));
		ulong quotient = x4 + Multiply(x4, MuLow, out _);
		// The 65th bit of q̂, which adds M·2^64.
		ulong mask = 0 - Carry(quotient, x4);
		ulong high = Multiply(quotient, M0, out ulong p0);
		high = MultiplyAdd(quotient, M1, high, 0, out ulong p1);
		high = MultiplyAdd(quotient, M2, high, 0, out ulong p2);
		ulong p4 = MultiplyAdd(quotient, M3, high, 0, out ulong p3);
		ulong carry = 0;
		p1 = AddWithCarry(p1, M0 & mask, ref carry);
		p2 = AddWithCarry(p2, M1 & mask, ref carry);
		p3 = AddWithCarry(p3, M2 & mask, ref carry);
		p4 = AddWithCarry(p4, M3 & mask, ref carry);
		// q̂·M is at most Ha, so nothing borrows out.
		ulong borrow = 0;
		ulong r0 = SubtractWithBorrow(x0, p0, ref borrow);
		ulong r1 = SubtractWithBorrow(x1, p1, ref borrow);
		ulong r2 = SubtractWithBorrow(x2, p2, ref borrow);
		ulong r3 = SubtractWithBorrow(x3, p3, ref borrow);
		ulong r4 = SubtractWithBorrow(x4, p4, ref borrow);
		SubtractModulus(ref r0, ref r1, ref r2, ref r3, ref r4);
		SubtractModulus(ref r0, ref r1, ref r2, ref r3, ref r4);
		Debug.Assert(r4 is 0);

		// r + 1 is at most M < 2^256, so it does not carry out.
		Unsafe.SkipInit(out result);
		Span<ulong> limbs = MemoryMarshal.Cast<FieldElement<SM9Order>, ulong>(new Span<FieldElement<SM9Order>>(ref result));
		carry = 1;
		limbs[0] = AddWithCarry(r0, 0, ref carry);
		limbs[1] = AddWithCarry(r1, 0, ref carry);
		limbs[2] = AddWithCarry(r2, 0, ref carry);
		limbs[3] = AddWithCarry(r3, 0, ref carry);
	}

	// r − M where that does not borrow, r otherwise.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void SubtractModulus(ref ulong r0, ref ulong r1, ref ulong r2, ref ulong r3, ref ulong r4)
	{
		ulong borrow = 0;
		ulong d0 = SubtractWithBorrow(r0, M0, ref borrow);
		ulong d1 = SubtractWithBorrow(r1, M1, ref borrow);
		ulong d2 = SubtractWithBorrow(r2, M2, ref borrow);
		ulong d3 = SubtractWithBorrow(r3, M3, ref borrow);
		ulong d4 = SubtractWithBorrow(r4, 0, ref borrow);
		// All ones where r is at least M.
		ulong keep = borrow - 1;
		r0 = Select(keep, d0, r0);
		r1 = Select(keep, d1, r1);
		r2 = Select(keep, d2, r2);
		r3 = Select(keep, d3, r3);
		r4 = Select(keep, d4, r4);
	}
}
