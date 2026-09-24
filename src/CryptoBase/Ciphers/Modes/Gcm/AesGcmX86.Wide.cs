using CryptoBase.Ciphers.Blocks.Aes;
using static CryptoBase.Ciphers.Blocks.Aes.AesCipherX86;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal static partial class AesGcmX86
{
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static int Encrypt8(in AesCipherX86 aes, ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination, ref Vector128<byte> accumulator, in GHashVector128PrecomputedKey powers)
	{
		int length = source.Length & -128;
		Debug.Assert(destination.Length >= length);

		if (length is 0)
		{
			return 0;
		}

		ref readonly AesKeys roundKeys = ref aes.RoundKeys;
		ref byte input = ref source.GetReference();
		ref byte output = ref destination.GetReference();
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

		Vector128<byte> v0 = NextCounter(ref prefix, ref value);
		Vector128<byte> v1 = NextCounter(ref prefix, ref value);
		Vector128<byte> v2 = NextCounter(ref prefix, ref value);
		Vector128<byte> v3 = NextCounter(ref prefix, ref value);
		Vector128<byte> v4 = NextCounter(ref prefix, ref value);
		Vector128<byte> v5 = NextCounter(ref prefix, ref value);
		Vector128<byte> v6 = NextCounter(ref prefix, ref value);
		Vector128<byte> v7 = NextCounter(ref prefix, ref value);
		aes.Encrypt8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
		AesGcmFusion.XorStore8(ref input, ref output, 0, ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
		Vector128<byte> hash = accumulator;

		for (nint offset = 128; offset < length; offset += 128)
		{
			v0 = NextCounter(ref prefix, ref value) ^ roundKeys.K0;
			v1 = NextCounter(ref prefix, ref value) ^ roundKeys.K0;
			v2 = NextCounter(ref prefix, ref value) ^ roundKeys.K0;
			v3 = NextCounter(ref prefix, ref value) ^ roundKeys.K0;
			v4 = NextCounter(ref prefix, ref value) ^ roundKeys.K0;
			v5 = NextCounter(ref prefix, ref value) ^ roundKeys.K0;
			v6 = NextCounter(ref prefix, ref value) ^ roundKeys.K0;
			v7 = NextCounter(ref prefix, ref value) ^ roundKeys.K0;

			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K1);
			MultiplyKaratsuba(Vector128.LoadUnsafe(ref output, (nuint)(offset - 128)).ReverseEndianness128() ^ hash, powers.GetKey(8), powers.GetXorKey(8), out Vector128<uint> p00, out Vector128<uint> p11, out Vector128<uint> pm);
			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K2);
			AccumulateKaratsubaBlock(Vector128.LoadUnsafe(ref output, (nuint)(offset - 112)), in powers, 7, ref p00, ref p11, ref pm);
			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K3);
			AccumulateKaratsubaBlock(Vector128.LoadUnsafe(ref output, (nuint)(offset - 96)), in powers, 6, ref p00, ref p11, ref pm);
			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K4);
			AccumulateKaratsubaBlock(Vector128.LoadUnsafe(ref output, (nuint)(offset - 80)), in powers, 5, ref p00, ref p11, ref pm);
			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K5);
			AccumulateKaratsubaBlock(Vector128.LoadUnsafe(ref output, (nuint)(offset - 64)), in powers, 4, ref p00, ref p11, ref pm);
			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K6);
			AccumulateKaratsubaBlock(Vector128.LoadUnsafe(ref output, (nuint)(offset - 48)), in powers, 3, ref p00, ref p11, ref pm);
			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K7);
			AccumulateKaratsubaBlock(Vector128.LoadUnsafe(ref output, (nuint)(offset - 32)), in powers, 2, ref p00, ref p11, ref pm);
			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K8);
			AccumulateKaratsubaBlock(Vector128.LoadUnsafe(ref output, (nuint)(offset - 16)), in powers, 1, ref p00, ref p11, ref pm);
			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K9);
			hash = ReduceKaratsuba(p00, p11, pm);
			aes.EncryptFinalRounds8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);

			AesGcmFusion.XorStore8(ref input, ref output, (nuint)offset, ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
		}

		MultiplyKaratsuba(v0.ReverseEndianness128() ^ hash, powers.GetKey(8), powers.GetXorKey(8), out Vector128<uint> lastP00, out Vector128<uint> lastP11, out Vector128<uint> lastPm);
		AccumulateKaratsubaBlock(v1, in powers, 7, ref lastP00, ref lastP11, ref lastPm);
		AccumulateKaratsubaBlock(v2, in powers, 6, ref lastP00, ref lastP11, ref lastPm);
		AccumulateKaratsubaBlock(v3, in powers, 5, ref lastP00, ref lastP11, ref lastPm);
		AccumulateKaratsubaBlock(v4, in powers, 4, ref lastP00, ref lastP11, ref lastPm);
		AccumulateKaratsubaBlock(v5, in powers, 3, ref lastP00, ref lastP11, ref lastPm);
		AccumulateKaratsubaBlock(v6, in powers, 2, ref lastP00, ref lastP11, ref lastPm);
		AccumulateKaratsubaBlock(v7, in powers, 1, ref lastP00, ref lastP11, ref lastPm);
		accumulator = ReduceKaratsuba(lastP00, lastP11, lastPm);
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
}
