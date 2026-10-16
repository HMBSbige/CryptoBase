using CryptoBase.Ciphers.Blocks.Aes;
using static CryptoBase.Ciphers.Blocks.Aes.AesCipherX86;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal static partial class AesGcmX86
{
	[MethodImpl(MethodImplOptions.NoInlining)]
	private static int Transform8Vector128<TDirection>(in AesCipherX86 aes, ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination, ref Vector128<byte> accumulator, in GHashVector128PrecomputedKey powers) where TDirection : struct, IBlockDirection
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

		Vector128<byte> hash = accumulator;
		ref byte hashInput = ref TDirection.IsDecrypt ? ref input : ref output;
		// Grouping each constant with the delay lets the JIT fold it into the load address.
		int hashDelay = TDirection.IsDecrypt ? 0 : 128;

		for (nint offset = TDirection.IsDecrypt ? 0 : 128; offset < length; offset += 128)
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
			MultiplyKaratsuba(Vector128.LoadUnsafe(ref hashInput, (nuint)(offset + (0 - hashDelay))).ReverseEndianness128() ^ hash, powers.GetKey(8), powers.GetXorKey(8), out Vector128<uint> p00, out Vector128<uint> p11, out Vector128<uint> pm);
			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K2);
			AccumulateKaratsubaBlock(Vector128.LoadUnsafe(ref hashInput, (nuint)(offset + (16 - hashDelay))), in powers, 7, ref p00, ref p11, ref pm);
			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K3);
			AccumulateKaratsubaBlock(Vector128.LoadUnsafe(ref hashInput, (nuint)(offset + (32 - hashDelay))), in powers, 6, ref p00, ref p11, ref pm);
			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K4);
			AccumulateKaratsubaBlock(Vector128.LoadUnsafe(ref hashInput, (nuint)(offset + (48 - hashDelay))), in powers, 5, ref p00, ref p11, ref pm);
			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K5);
			AccumulateKaratsubaBlock(Vector128.LoadUnsafe(ref hashInput, (nuint)(offset + (64 - hashDelay))), in powers, 4, ref p00, ref p11, ref pm);
			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K6);
			AccumulateKaratsubaBlock(Vector128.LoadUnsafe(ref hashInput, (nuint)(offset + (80 - hashDelay))), in powers, 3, ref p00, ref p11, ref pm);
			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K7);
			AccumulateKaratsubaBlock(Vector128.LoadUnsafe(ref hashInput, (nuint)(offset + (96 - hashDelay))), in powers, 2, ref p00, ref p11, ref pm);
			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K8);
			AccumulateKaratsubaBlock(Vector128.LoadUnsafe(ref hashInput, (nuint)(offset + (112 - hashDelay))), in powers, 1, ref p00, ref p11, ref pm);
			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K9);
			hash = ReduceKaratsuba(p00, p11, pm);
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
}
