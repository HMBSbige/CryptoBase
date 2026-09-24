using CryptoBase.Ciphers.Blocks.Aes;
using static CryptoBase.Ciphers.Blocks.Aes.AesCipherArm;
using AesArm = System.Runtime.Intrinsics.Arm.Aes;

namespace CryptoBase.Ciphers.Modes.Gcm;

internal static partial class AesGcmArm
{
	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static int Encrypt8(in AesCipherArm aes, ref Vector128<byte> counter, ReadOnlySpan<byte> source, Span<byte> destination, ref Vector128<byte> accumulator, in GHashArmPrecomputedKey powers, ref Vector128<byte> tagMask)
	{
		int length = source.Length & -128;
		Debug.Assert(destination.Length >= length);

		if (length is 0)
		{
			return 0;
		}

		ref byte input = ref source.GetReference();
		ref byte output = ref destination.GetReference();
		ref readonly AesKeys roundKeys = ref aes.RoundKeys;
		Vector128<uint> counterState = counter.ReverseEndianness32().AsUInt32();
		Vector128<byte> c0 = NextCounter(ref counterState);
		Vector128<byte> c1 = NextCounter(ref counterState);
		Vector128<byte> c2 = NextCounter(ref counterState);
		Vector128<byte> c3 = NextCounter(ref counterState);
		Vector128<byte> c4 = NextCounter(ref counterState);
		Vector128<byte> c5 = NextCounter(ref counterState);
		Vector128<byte> c6 = NextCounter(ref counterState);
		Vector128<byte> c7 = NextCounter(ref counterState);

		Vector128<byte> tagState = tagMask;
		EncryptFirstBatch9(in aes, ref c0, ref c1, ref c2, ref c3, ref c4, ref c5, ref c6, ref c7, ref tagState);
		tagMask = tagState;

		AesGcmFusion.XorStore8(ref input, ref output, 0, ref c0, ref c1, ref c2, ref c3, ref c4, ref c5, ref c6, ref c7);
		Vector128<byte> hash = accumulator;
		Vector128<byte> h8 = powers.Key8;
		Vector128<byte> h7 = powers.Key7;
		Vector128<byte> h6 = powers.Key6;
		Vector128<byte> h5 = powers.Key5;

		for (nint offset = 128; offset < length; offset += 128)
		{
			Vector128<byte> v0 = NextCounter(ref counterState);
			Vector128<byte> v1 = NextCounter(ref counterState);
			Vector128<byte> v2 = NextCounter(ref counterState);
			Vector128<byte> v3 = NextCounter(ref counterState);
			Vector128<byte> v4 = NextCounter(ref counterState);
			Vector128<byte> v5 = NextCounter(ref counterState);
			Vector128<byte> v6 = NextCounter(ref counterState);
			Vector128<byte> v7 = NextCounter(ref counterState);

			Vector128<ulong> low = default;
			Vector128<ulong> high = default;
			Vector128<ulong> middle = default;
			EncryptHashRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K0, AdvSimd.Arm64.ReverseElementBits(c0) ^ hash, h8, ref low, ref high, ref middle, true);
			EncryptHashRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K1, AdvSimd.Arm64.ReverseElementBits(c1), h7, ref low, ref high, ref middle, false);
			EncryptHashRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K2, AdvSimd.Arm64.ReverseElementBits(c2), h6, ref low, ref high, ref middle, false);
			EncryptHashRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K3, AdvSimd.Arm64.ReverseElementBits(c3), h5, ref low, ref high, ref middle, false);
			EncryptHashRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K4, AdvSimd.Arm64.ReverseElementBits(c4), powers.Key4, ref low, ref high, ref middle, false);
			EncryptHashRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K5, AdvSimd.Arm64.ReverseElementBits(c5), powers.Key3, ref low, ref high, ref middle, false);
			EncryptHashRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K6, AdvSimd.Arm64.ReverseElementBits(c6), powers.Key2, ref low, ref high, ref middle, false);
			EncryptHashRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K7, AdvSimd.Arm64.ReverseElementBits(c7), powers.Key1, ref low, ref high, ref middle, false);
			EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, roundKeys.K8);
			hash = GHashArm.ReduceSchoolbookProduct(low, high, middle);
			aes.EncryptFinalRounds8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);

			c0 = v0;
			c1 = v1;
			c2 = v2;
			c3 = v3;
			c4 = v4;
			c5 = v5;
			c6 = v6;
			c7 = v7;
			AesGcmFusion.XorStore8(ref input, ref output, (nuint)offset, ref c0, ref c1, ref c2, ref c3, ref c4, ref c5, ref c6, ref c7);
		}

		GHashArm.GFMultiplyUnreduced(AdvSimd.Arm64.ReverseElementBits(c0) ^ hash, h8, out Vector128<ulong> finalLow, out Vector128<ulong> finalHigh, out Vector128<ulong> finalMiddle);
		GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c1), h7, ref finalLow, ref finalHigh, ref finalMiddle);
		GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c2), h6, ref finalLow, ref finalHigh, ref finalMiddle);
		GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c3), h5, ref finalLow, ref finalHigh, ref finalMiddle);
		GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c4), powers.Key4, ref finalLow, ref finalHigh, ref finalMiddle);
		GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c5), powers.Key3, ref finalLow, ref finalHigh, ref finalMiddle);
		GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c6), powers.Key2, ref finalLow, ref finalHigh, ref finalMiddle);
		GHashArm.AccumulateProduct(AdvSimd.Arm64.ReverseElementBits(c7), powers.Key1, ref finalLow, ref finalHigh, ref finalMiddle);
		accumulator = ReduceHash(finalLow, finalHigh, finalMiddle);
		counter = counterState.ReverseEndianness32().AsByte();
		return length;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> NextCounter(ref Vector128<uint> counter)
	{
		Vector128<byte> next = counter.ReverseEndianness32().AsByte();
		counter += Vector128.Create(0u, 0, 0, 1);
		return next;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void EncryptHashRound8(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7, Vector128<byte> roundKey, Vector128<byte> value, Vector128<byte> hashKey, ref Vector128<ulong> low, ref Vector128<ulong> high, ref Vector128<ulong> middle, bool initialize)
	{
		Vector128<ulong> a = value.AsUInt64();
		Vector128<ulong> b = hashKey.AsUInt64();
		Vector64<ulong> aLow = a.GetLower();
		Vector64<ulong> bLow = b.GetLower();

		v0 = AesArm.MixColumns(AesArm.Encrypt(v0, roundKey));
		Vector128<ulong> lowProduct = AesArm.PolynomialMultiplyWideningLower(aLow, bLow);
		v1 = AesArm.MixColumns(AesArm.Encrypt(v1, roundKey));
		Vector128<ulong> highProduct = AesArm.PolynomialMultiplyWideningUpper(a, b);
		v2 = AesArm.MixColumns(AesArm.Encrypt(v2, roundKey));
		Vector128<ulong> swapped = AdvSimd.ExtractVector128(a, a, 1);
		v3 = AesArm.MixColumns(AesArm.Encrypt(v3, roundKey));
		Vector128<ulong> middleLow = AesArm.PolynomialMultiplyWideningLower(swapped.GetLower(), bLow);
		v4 = AesArm.MixColumns(AesArm.Encrypt(v4, roundKey));
		low = initialize ? lowProduct : low ^ lowProduct;
		v5 = AesArm.MixColumns(AesArm.Encrypt(v5, roundKey));
		Vector128<ulong> middleHigh = AesArm.PolynomialMultiplyWideningUpper(swapped, b);
		v6 = AesArm.MixColumns(AesArm.Encrypt(v6, roundKey));
		high = initialize ? highProduct : high ^ highProduct;
		v7 = AesArm.MixColumns(AesArm.Encrypt(v7, roundKey));
		middle = initialize ? middleLow ^ middleHigh : middle ^ middleLow ^ middleHigh;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void EncryptFirstBatch9(in AesCipherArm aes, ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7, ref Vector128<byte> tagState)
	{
		ref readonly AesKeys roundKeys = ref aes.RoundKeys;

		EncryptRound9(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref tagState, roundKeys.K0);
		EncryptRound9(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref tagState, roundKeys.K1);
		EncryptRound9(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref tagState, roundKeys.K2);
		EncryptRound9(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref tagState, roundKeys.K3);
		EncryptRound9(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref tagState, roundKeys.K4);
		EncryptRound9(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref tagState, roundKeys.K5);
		EncryptRound9(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref tagState, roundKeys.K6);
		EncryptRound9(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref tagState, roundKeys.K7);
		EncryptRound9(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref tagState, roundKeys.K8);

		if (aes.RoundKeyCount is 11)
		{
			EncryptLastRound9(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref tagState, roundKeys.K9, roundKeys.K10);
			return;
		}

		EncryptRound9(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref tagState, roundKeys.K9);
		EncryptRound9(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref tagState, roundKeys.K10);

		if (aes.RoundKeyCount is 13)
		{
			EncryptLastRound9(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref tagState, roundKeys.K11, roundKeys.K12);
			return;
		}

		EncryptRound9(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref tagState, roundKeys.K11);
		EncryptRound9(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref tagState, roundKeys.K12);
		EncryptLastRound9(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, ref tagState, roundKeys.K13, roundKeys.K14);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void EncryptRound9(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7, ref Vector128<byte> tagState, Vector128<byte> key)
	{
		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, key);
		tagState = AesArm.MixColumns(AesArm.Encrypt(tagState, key));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void EncryptLastRound9(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7, ref Vector128<byte> tagState, Vector128<byte> key, Vector128<byte> lastKey)
	{
		EncryptLastRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, key, lastKey);
		tagState = AesArm.Encrypt(tagState, key) ^ lastKey;
	}
}
