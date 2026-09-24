using CryptoBase.Ciphers.Blocks.Aes;
using static CryptoBase.Ciphers.Blocks.Aes.AesCipherX86;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal static partial class AesGcmX86
{
	private const int WideThreshold = 1024;

	internal static int Encrypt(in AesCipherX86 aes, ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination, ref GHashKey hashKey, ref Vector128<byte> accumulator, ref Vector128<byte> tagMask)
	{
		tagMask = aes.Encrypt(tagMask);
		ref readonly GHashVector128PrecomputedKey powers = ref hashKey.GetVector128().Value;
		accumulator = accumulator.ReverseEndianness128();
		int processed = source.Length >= WideThreshold
			? Encrypt8(in aes, ref counter, source, destination, ref accumulator, in powers)
			: 0;

		if (source.Length - processed >= 64)
		{
			processed += Encrypt4(in aes, ref counter, source.Slice(processed), destination.Slice(processed), ref accumulator, in powers);
		}

		accumulator = accumulator.ReverseEndianness128();
		return processed;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static int Encrypt4(in AesCipherX86 aes, ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination, ref Vector128<byte> accumulator, in GHashVector128PrecomputedKey powers)
	{
		int length = source.Length & -64;
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

		if (!Sse41.IsSupported)
		{
			prefix &= Vector128.Create(uint.MaxValue, uint.MaxValue, uint.MaxValue, 0u).AsByte();
		}

		Vector128<byte> c0 = CreateCounter(prefix, value);
		Vector128<byte> c1 = CreateCounter(prefix, value + 1u);
		Vector128<byte> c2 = CreateCounter(prefix, value + 2u);
		Vector128<byte> c3 = CreateCounter(prefix, value + 3u);
		aes.Encrypt4(ref c0, ref c1, ref c2, ref c3);
		c0 ^= Vector128.LoadUnsafe(ref input, 0);
		c0.StoreUnsafe(ref output, 0);
		c1 ^= Vector128.LoadUnsafe(ref input, 16);
		c1.StoreUnsafe(ref output, 16);
		c2 ^= Vector128.LoadUnsafe(ref input, 32);
		c2.StoreUnsafe(ref output, 32);
		c3 ^= Vector128.LoadUnsafe(ref input, 48);
		c3.StoreUnsafe(ref output, 48);
		value += 4u;

		Vector128<byte> hash = accumulator;

		for (int offset = 64; offset < length; offset += 64)
		{
			Vector128<byte> v0 = CreateCounter(prefix, value) ^ roundKeys.K0;
			Vector128<byte> v1 = CreateCounter(prefix, value + 1u) ^ roundKeys.K0;
			Vector128<byte> v2 = CreateCounter(prefix, value + 2u) ^ roundKeys.K0;
			Vector128<byte> v3 = CreateCounter(prefix, value + 3u) ^ roundKeys.K0;

			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K1);
			MultiplyBlock(c0, hash, in powers, 4, out Vector128<byte> lo, out Vector128<byte> hi);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K2);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K3);
			AccumulateBlock(c1, in powers, 3, ref lo, ref hi);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K4);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K5);
			AccumulateBlock(c2, in powers, 2, ref lo, ref hi);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K6);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K7);
			AccumulateBlock(c3, in powers, 1, ref lo, ref hi);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K8);
			hash = GHashX86.ReducePrepared(lo, hi);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K9);
			aes.EncryptFinalRounds4(ref v0, ref v1, ref v2, ref v3);

			c0 = v0 ^ Vector128.LoadUnsafe(ref input, (nuint)offset);
			c0.StoreUnsafe(ref output, (nuint)offset);
			c1 = v1 ^ Vector128.LoadUnsafe(ref input, (nuint)(offset + 16));
			c1.StoreUnsafe(ref output, (nuint)(offset + 16));
			c2 = v2 ^ Vector128.LoadUnsafe(ref input, (nuint)(offset + 32));
			c2.StoreUnsafe(ref output, (nuint)(offset + 32));
			c3 = v3 ^ Vector128.LoadUnsafe(ref input, (nuint)(offset + 48));
			c3.StoreUnsafe(ref output, (nuint)(offset + 48));
			value += 4u;
		}

		MultiplyBlock(c0, hash, in powers, 4, out Vector128<byte> lastLo, out Vector128<byte> lastHi);
		AccumulateBlock(c1, in powers, 3, ref lastLo, ref lastHi);
		AccumulateBlock(c2, in powers, 2, ref lastLo, ref lastHi);
		AccumulateBlock(c3, in powers, 1, ref lastLo, ref lastHi);
		accumulator = GHashX86.ReducePrepared(lastLo, lastHi);
		counter = CreateCounter(prefix, value);
		return length;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> CreateCounter(Vector128<byte> prefix, uint value)
	{
		uint bigEndianValue = BinaryPrimitives.ReverseEndianness(value);

		if (Sse41.IsSupported)
		{
			return prefix.AsUInt32().WithElement(3, bigEndianValue).AsByte();
		}

		return prefix | Sse2.ShiftLeftLogical128BitLane(Vector128.CreateScalar(bigEndianValue).AsByte(), 12);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MultiplyBlock(Vector128<byte> ciphertext, Vector128<byte> accumulator, in GHashVector128PrecomputedKey powers, int power, out Vector128<byte> lo, out Vector128<byte> hi)
	{
		Vector128<byte> block = ciphertext.ReverseEndianness128() ^ accumulator;
		GHashX86.GFMultiplyPreparedUnreduced(block, powers.GetKey(power), powers.GetReductionKey(power), out lo, out hi);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void AccumulateBlock(Vector128<byte> ciphertext, in GHashVector128PrecomputedKey powers, int power, ref Vector128<byte> lo, ref Vector128<byte> hi)
	{
		GHashX86.GFMultiplyPreparedUnreduced(ciphertext.ReverseEndianness128(), powers.GetKey(power), powers.GetReductionKey(power), out Vector128<byte> nextLo, out Vector128<byte> nextHi);
		lo ^= nextLo;
		hi ^= nextHi;
	}
}
