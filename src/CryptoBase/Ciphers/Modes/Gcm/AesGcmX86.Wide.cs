using CryptoBase.Ciphers.Blocks.Aes;
using static CryptoBase.Ciphers.Blocks.Aes.AesCipherX86;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal static partial class AesGcmX86
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static int Transform8<TDirection>(in AesCipherX86 aes, ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination, ref Vector128<byte> accumulator, in GHashVector128PrecomputedKey powers) where TDirection : struct, IBlockDirection
	{
		return GHashX86.IsSupported256
			? Transform8Avx<TDirection>(in aes, ref counter, source, destination, ref accumulator, in powers)
			: Transform8Vector128<TDirection>(in aes, ref counter, source, destination, ref accumulator, in powers);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static int Transform8Avx<TDirection>(in AesCipherX86 aes, ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination, ref Vector128<byte> accumulator, in GHashVector128PrecomputedKey powers) where TDirection : struct, IBlockDirection
	{
		int length = source.Length & -128;
		Debug.Assert(destination.Length >= length);

		if (length is 0)
		{
			return 0;
		}

		ref readonly AesKeys roundKeys = ref aes.RoundKeys;
		ref byte input = ref MemoryMarshal.GetReference(source);
		ref byte output = ref MemoryMarshal.GetReference(destination);
		Vector128<byte> prefix = counter;
		uint value = BinaryPrimitives.ReadUInt32BigEndian(counter.AsReadOnlySpan().Slice(12));

		if (Ssse3.IsSupported)
		{
			prefix = prefix.ReverseEndianness128();
		}
		else if (!Sse41.IsSupported)
		{
			prefix &= Vector128.Create(uint.MaxValue, uint.MaxValue, uint.MaxValue, 0u).AsByte();
		}

		Vector128<byte> v0 = default, v1 = default, v2 = default, v3 = default, v4 = default, v5 = default, v6 = default, v7 = default;

		if (!TDirection.IsDecrypt)
		{
			v0 = NextCounter(ref prefix, ref value);
			v1 = NextCounter(ref prefix, ref value);
			v2 = NextCounter(ref prefix, ref value);
			v3 = NextCounter(ref prefix, ref value);
			v4 = NextCounter(ref prefix, ref value);
			v5 = NextCounter(ref prefix, ref value);
			v6 = NextCounter(ref prefix, ref value);
			v7 = NextCounter(ref prefix, ref value);
			aes.Encrypt8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
			BlockXor.XorStore8(ref input, ref output, 0, ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
		}

		Vector512<byte> key8 = default, reductionKey8 = default, key4 = default, reductionKey4 = default;

		if (GHashX86.IsSupported512)
		{
			LoadFourPowers(in powers, 8, out key8, out reductionKey8);
			LoadFourPowers(in powers, 4, out key4, out reductionKey4);
		}

		Vector128<byte> hash = accumulator;
		ref byte hashInput = ref TDirection.IsDecrypt ? ref input : ref output;

		for (nint offset = TDirection.IsDecrypt ? 0 : 128; offset < length; offset += 128)
		{
			nint hashOffset = TDirection.IsDecrypt ? offset : offset - 128;
			Vector512<byte> ciphertext0 = default, ciphertext1 = default;

			if (!TDirection.IsDecrypt && GHashX86.IsSupported512)
			{
				// Build from registers: a wide load right after the previous batch's narrow stores cannot be store-forwarded.
				ciphertext0 = Vector512.Create(Vector256.Create(v0, v1), Vector256.Create(v2, v3));
				ciphertext1 = Vector512.Create(Vector256.Create(v4, v5), Vector256.Create(v6, v7));
			}

			v0 = NextCounter(ref prefix, ref value) ^ roundKeys.K0;
			v1 = NextCounter(ref prefix, ref value) ^ roundKeys.K0;
			v2 = NextCounter(ref prefix, ref value) ^ roundKeys.K0;
			v3 = NextCounter(ref prefix, ref value) ^ roundKeys.K0;
			v4 = NextCounter(ref prefix, ref value) ^ roundKeys.K0;
			v5 = NextCounter(ref prefix, ref value) ^ roundKeys.K0;
			v6 = NextCounter(ref prefix, ref value) ^ roundKeys.K0;
			v7 = NextCounter(ref prefix, ref value) ^ roundKeys.K0;

			Vector512<byte> lo512 = default, hi512 = default;
			Vector256<byte> lo = default, hi = default;
			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K1);

			if (GHashX86.IsSupported512)
			{
				Vector512<byte> block = (TDirection.IsDecrypt ? Vector512.LoadUnsafe(ref hashInput, (nuint)hashOffset) : ciphertext0).ReverseEndianness128() ^ hash.ToVector256().ToVector512();
				GHashX86.GFMultiplyPreparedUnreduced(block, key8, reductionKey8, out lo512, out hi512);
			}
			else
			{
				Vector256<byte> block = Vector256.LoadUnsafe(ref hashInput, (nuint)hashOffset).ReverseEndianness128() ^ hash.ToVector256();
				MultiplyPair(block, in powers, 8, out lo, out hi);
			}

			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K2);
			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K3);

			if (!GHashX86.IsSupported512)
			{
				AccumulatePair(ref Unsafe.Add(ref hashInput, hashOffset + 32), in powers, 6, ref lo, ref hi);
			}

			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K4);
			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K5);

			if (GHashX86.IsSupported512)
			{
				GHashX86.GFMultiplyPreparedUnreduced((TDirection.IsDecrypt ? Vector512.LoadUnsafe(ref hashInput, (nuint)(hashOffset + 64)) : ciphertext1).ReverseEndianness128(), key4, reductionKey4, out Vector512<byte> nextLo, out Vector512<byte> nextHi);
				lo512 ^= nextLo;
				hi512 ^= nextHi;
			}
			else
			{
				AccumulatePair(ref Unsafe.Add(ref hashInput, hashOffset + 64), in powers, 4, ref lo, ref hi);
			}

			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K6);
			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K7);

			if (!GHashX86.IsSupported512)
			{
				AccumulatePair(ref Unsafe.Add(ref hashInput, hashOffset + 96), in powers, 2, ref lo, ref hi);
			}

			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K8);
			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K9);
			hash = GHashX86.IsSupported512 ? GHashX86.ReducePreparedTo128(lo512, hi512) : GHashX86.ReducePreparedTo128(lo, hi);
			aes.EncryptFinalRounds8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);

			BlockXor.XorStore8(ref input, ref output, (nuint)offset, ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
		}

		if (!TDirection.IsDecrypt)
		{
			MultiplyKaratsuba(v0.ReverseEndianness128() ^ hash, powers.GetKey(8), powers.GetXorKey(8), out Vector128<uint> lastP00, out Vector128<uint> lastP11, out Vector128<uint> lastPm);
			AccumulateKaratsubaBlock(v1, in powers, 7, ref lastP00, ref lastP11, ref lastPm);
			AccumulateKaratsubaBlock(v2, in powers, 6, ref lastP00, ref lastP11, ref lastPm);
			AccumulateKaratsubaBlock(v3, in powers, 5, ref lastP00, ref lastP11, ref lastPm);
			AccumulateKaratsubaBlock(v4, in powers, 4, ref lastP00, ref lastP11, ref lastPm);
			AccumulateKaratsubaBlock(v5, in powers, 3, ref lastP00, ref lastP11, ref lastPm);
			AccumulateKaratsubaBlock(v6, in powers, 2, ref lastP00, ref lastP11, ref lastPm);
			AccumulateKaratsubaBlock(v7, in powers, 1, ref lastP00, ref lastP11, ref lastPm);
			hash = ReduceKaratsuba(lastP00, lastP11, lastPm);
		}

		accumulator = hash;
		counter = Ssse3.IsSupported ? prefix.ReverseEndianness128() : CreateCounter(prefix, value);
		return length;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> NextCounter(ref Vector128<byte> prefix, ref uint value)
	{
		if (Ssse3.IsSupported)
		{
			Vector128<byte> next = prefix.ReverseEndianness128();
			prefix = prefix.IncUInt32LE();
			return next;
		}

		Vector128<byte> result = CreateCounter(prefix, value);
		++value;
		return result;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MultiplyKaratsuba(Vector128<byte> value, Vector128<byte> key, Vector128<byte> keyXor, out Vector128<uint> p00, out Vector128<uint> p11, out Vector128<uint> pm)
	{
		p00 = Pclmulqdq.CarrylessMultiply(value.AsUInt64(), key.AsUInt64(), 0x00).AsUInt32();
		p11 = Pclmulqdq.CarrylessMultiply(value.AsUInt64(), key.AsUInt64(), 0x11).AsUInt32();
		Vector128<byte> blockSum = value ^ Sse2.ShiftRightLogical128BitLane(value, 8);
		pm = Pclmulqdq.CarrylessMultiply(blockSum.AsUInt64(), keyXor.AsUInt64(), 0x00).AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AccumulateKaratsubaBlock(Vector128<byte> ciphertext, in GHashVector128PrecomputedKey powers, int power, ref Vector128<uint> p00, ref Vector128<uint> p11, ref Vector128<uint> pm)
	{
		Vector128<ulong> block = ciphertext.ReverseEndianness128().AsUInt64();
		Vector128<ulong> key64 = powers.GetKey(power).AsUInt64();
		p00 ^= Pclmulqdq.CarrylessMultiply(block, key64, 0x00).AsUInt32();
		p11 ^= Pclmulqdq.CarrylessMultiply(block, key64, 0x11).AsUInt32();
		Vector128<ulong> blockSum = block ^ Sse2.ShiftRightLogical128BitLane(block, 8);
		pm ^= Pclmulqdq.CarrylessMultiply(blockSum, powers.GetXorKey(power).AsUInt64(), 0x00).AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> ReduceKaratsuba(Vector128<uint> p00, Vector128<uint> p11, Vector128<uint> pm)
	{
		GHashX86.AssembleProduct(p00, p11, pm, out Vector128<uint> lo, out Vector128<uint> hi);
		// Prepared powers include x, so skip the initial doubling.
		Vector128<uint> polynomial = lo << 31 ^ lo << 30 ^ lo << 25;
		Vector128<uint> folded = lo ^ Sse2.ShiftLeftLogical128BitLane(polynomial, 12);
		return (hi ^ folded ^ folded >>> 1 ^ folded >>> 2 ^ folded >>> 7 ^ Sse2.ShiftRightLogical128BitLane(polynomial, 4)).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MultiplyPair(Vector256<byte> value, in GHashVector128PrecomputedKey powers, int power, out Vector256<byte> lo, out Vector256<byte> hi)
	{
		Vector256<byte> key = Vector256.Create(powers.GetKey(power), powers.GetKey(power - 1));
		Vector256<byte> reductionKey = Vector256.Create(powers.GetReductionKey(power), powers.GetReductionKey(power - 1));
		GHashX86.GFMultiplyPreparedUnreduced(value, key, reductionKey, out lo, out hi);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AccumulatePair(ref byte ciphertext, in GHashVector128PrecomputedKey powers, int power, ref Vector256<byte> lo, ref Vector256<byte> hi)
	{
		MultiplyPair(Vector256.LoadUnsafe(ref ciphertext).ReverseEndianness128(), in powers, power, out Vector256<byte> nextLo, out Vector256<byte> nextHi);
		lo ^= nextLo;
		hi ^= nextHi;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void LoadFourPowers(in GHashVector128PrecomputedKey powers, int power, out Vector512<byte> key, out Vector512<byte> reductionKey)
	{
		key = Vector256.Create(powers.GetKey(power), powers.GetKey(power - 1)).ToVector512Unsafe().WithUpper(Vector256.Create(powers.GetKey(power - 2), powers.GetKey(power - 3)));
		reductionKey = Vector256.Create(powers.GetReductionKey(power), powers.GetReductionKey(power - 1)).ToVector512Unsafe().WithUpper(Vector256.Create(powers.GetReductionKey(power - 2), powers.GetReductionKey(power - 3)));
	}
}
