using CryptoBase.Ciphers.Blocks.Aes;
using static CryptoBase.Ciphers.Blocks.Aes.AesCipherArm;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal static partial class AesGcmArm
{
	private const int WideThreshold = 512;

	internal static int Encrypt(in AesCipherArm aes, ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination, ref GHashKey hashKey, ref Vector128<byte> accumulator, ref Vector128<byte> tagMask)
	{
		ref readonly GHashArmPrecomputedKey powers = ref hashKey.GetArm().Value;
		accumulator = AdvSimd.Arm64.ReverseElementBits(accumulator);
		int processed = 0;

		if (source.Length >= WideThreshold)
		{
			processed = Encrypt8(in aes, ref counter, source, destination, ref accumulator, in powers, ref tagMask);
		}
		else
		{
			tagMask = aes.Encrypt(tagMask);
		}

		if (source.Length - processed >= 64)
		{
			processed += Encrypt4(in aes, ref counter, source.Slice(processed), destination.Slice(processed), ref accumulator, in powers);
		}

		accumulator = AdvSimd.Arm64.ReverseElementBits(accumulator);
		return processed;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static int Encrypt4(in AesCipherArm aes, ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination, ref Vector128<byte> accumulator, in GHashArmPrecomputedKey powers)
	{
		int length = source.Length & -64;
		Debug.Assert(destination.Length >= length);

		if (length is 0)
		{
			return 0;
		}

		ref byte input = ref source.GetReference();
		ref byte output = ref destination.GetReference();
		ref readonly AesKeys roundKeys = ref aes.RoundKeys;
		uint value = BinaryPrimitives.ReverseEndianness(counter.AsUInt32().GetElement(3));
		Vector128<uint> prefix = counter.AsUInt32().WithElement(3, 0U);
		Vector128<byte> c0 = CreateCounter(prefix, value);
		Vector128<byte> c1 = CreateCounter(prefix, value + 1);
		Vector128<byte> c2 = CreateCounter(prefix, value + 2);
		Vector128<byte> c3 = CreateCounter(prefix, value + 3);
		value += 4;
		aes.Encrypt4(ref c0, ref c1, ref c2, ref c3);
		c0 ^= Vector128.LoadUnsafe(ref input, 0);
		c1 ^= Vector128.LoadUnsafe(ref input, 16);
		c2 ^= Vector128.LoadUnsafe(ref input, 32);
		c3 ^= Vector128.LoadUnsafe(ref input, 48);
		c0.StoreUnsafe(ref output, 0);
		c1.StoreUnsafe(ref output, 16);
		c2.StoreUnsafe(ref output, 32);
		c3.StoreUnsafe(ref output, 48);

		Vector128<byte> hash = accumulator;

		for (int offset = 64; offset < length; offset += 64)
		{
			Vector128<byte> v0 = CreateCounter(prefix, value);
			Vector128<byte> v1 = CreateCounter(prefix, value + 1);
			Vector128<byte> v2 = CreateCounter(prefix, value + 2);
			Vector128<byte> v3 = CreateCounter(prefix, value + 3);
			value += 4;

			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K0);
			GHashArm.GFMultiplyUnreduced(AdvSimd.Arm64.ReverseElementBits(c0) ^ hash, powers.Key4, out Vector128<ulong> low, out Vector128<ulong> high, out Vector128<ulong> middle);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K1);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K2);
			GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c1), powers.Key3, ref low, ref high, ref middle);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K3);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K4);
			GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c2), powers.Key2, ref low, ref high, ref middle);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K5);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K6);
			GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c3), powers.Key1, ref low, ref high, ref middle);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K7);
			EncryptRound4(ref v0, ref v1, ref v2, ref v3, roundKeys.K8);
			hash = ReduceHash(low, high, middle);
			aes.EncryptFinalRounds4(ref v0, ref v1, ref v2, ref v3);

			c0 = v0 ^ Vector128.LoadUnsafe(ref input, (nuint)offset);
			c1 = v1 ^ Vector128.LoadUnsafe(ref input, (nuint)(offset + 16));
			c2 = v2 ^ Vector128.LoadUnsafe(ref input, (nuint)(offset + 32));
			c3 = v3 ^ Vector128.LoadUnsafe(ref input, (nuint)(offset + 48));
			c0.StoreUnsafe(ref output, (nuint)offset);
			c1.StoreUnsafe(ref output, (nuint)(offset + 16));
			c2.StoreUnsafe(ref output, (nuint)(offset + 32));
			c3.StoreUnsafe(ref output, (nuint)(offset + 48));
		}

		GHashArm.GFMultiplyUnreduced(AdvSimd.Arm64.ReverseElementBits(c0) ^ hash, powers.Key4, out Vector128<ulong> finalLow, out Vector128<ulong> finalHigh, out Vector128<ulong> finalMiddle);
		GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c1), powers.Key3, ref finalLow, ref finalHigh, ref finalMiddle);
		GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c2), powers.Key2, ref finalLow, ref finalHigh, ref finalMiddle);
		GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c3), powers.Key1, ref finalLow, ref finalHigh, ref finalMiddle);
		accumulator = ReduceHash(finalLow, finalHigh, finalMiddle);
		counter = CreateCounter(prefix, value);
		return length;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> CreateCounter(Vector128<uint> prefix, uint value)
	{
		return prefix.WithElement(3, BinaryPrimitives.ReverseEndianness(value)).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> ReduceHash(Vector128<ulong> low, Vector128<ulong> high, Vector128<ulong> middle)
	{
		GHashArm.AssembleProduct(low, high, middle, out Vector128<uint> productLow, out Vector128<uint> productHigh);
		return GHashArm.Reduce(productLow, productHigh);
	}
}
