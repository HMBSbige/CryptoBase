namespace CryptoBase.Ciphers.Blocks.Aes;

internal struct AesCipherVpaes : IDisposable
{
	public static bool IsSupported => Ssse3.IsSupported;

	private readonly int _rounds;
	private InlineArray15<Vector128<byte>> _roundKeys;
	private InlineArray15<Vector128<byte>> _reverseRoundKeys;

	private static Vector128<byte> InverseLookupTable => Vector128.Create(0x0E05060F0D080180UL, 0x040703090A0B0C02UL).AsByte();

	private static Vector128<byte> InverseAdjustmentTable => Vector128.Create(0x01040A060F0B0780UL, 0x030D0E0C02050809UL).AsByte();

	private static Vector128<byte> EncryptionInputTransformLow => Vector128.Create(0xC2B2E8985A2A7000UL, 0xCABAE09052227808UL).AsByte();

	private static Vector128<byte> EncryptionInputTransformHigh => Vector128.Create(0x4C01307D317C4D00UL, 0xCD80B1FCB0FDCC81UL).AsByte();

	private static Vector128<byte> SBoxStage1Table0 => Vector128.Create(0xB19BE18FCB503E00UL, 0xA5DF7A6E142AF544UL).AsByte();

	private static Vector128<byte> SBoxStage1Table1 => Vector128.Create(0x3618D415FAE22300UL, 0x3BF7CCC10D2ED9EFUL).AsByte();

	private static Vector128<byte> SBoxStage2Table0 => Vector128.Create(0xE27A93C60B712400UL, 0x5EB7E955BC982FCDUL).AsByte();

	private static Vector128<byte> SBoxStage2Table1 => Vector128.Create(0x69EB88400AE12900UL, 0xC2A163C8AB82234AUL).AsByte();

	private static Vector128<byte> SBoxOutputTable0 => Vector128.Create(0xD0D26D176FBDC700UL, 0x15AABF7AC502A878UL).AsByte();

	private static Vector128<byte> SBoxOutputTable1 => Vector128.Create(0xCFE474A55FBB6A00UL, 0x8E1E90D1412B35FAUL).AsByte();

	private static Vector128<byte> DecryptionInputTransformLow => Vector128.Create(0x0F505B040B545F00UL, 0x154A411E114E451AUL).AsByte();

	private static Vector128<byte> DecryptionInputTransformHigh => Vector128.Create(0x86E383E660056500UL, 0x12771772F491F194UL).AsByte();

	private static Vector128<byte> DecryptionSBoxOutputTimes9Table0 => Vector128.Create(0x851C03539A86D600UL, 0xCAD51F504F994CC9UL).AsByte();

	private static Vector128<byte> DecryptionSBoxOutputTimes9Table1 => Vector128.Create(0xC03B1789ECD74900UL, 0x725E2C9EB2FBA565UL).AsByte();

	private static Vector128<byte> DecryptionSBoxOutputTimes13Table0 => Vector128.Create(0x7D57CCDFE6B1A200UL, 0xF56E9B13882A4439UL).AsByte();

	private static Vector128<byte> DecryptionSBoxOutputTimes13Table1 => Vector128.Create(0x3CE2FAF724C6CB00UL, 0x2931180D15DEEFD3UL).AsByte();

	private static Vector128<byte> DecryptionSBoxOutputTimes11Table0 => Vector128.Create(0xD022649296B44200UL, 0x602646F6B0F2D404UL).AsByte();

	private static Vector128<byte> DecryptionSBoxOutputTimes11Table1 => Vector128.Create(0xC19498A6CD596700UL, 0xF3FF0C3E3255AA6BUL).AsByte();

	private static Vector128<byte> DecryptionSBoxOutputTimes14Table0 => Vector128.Create(0x46F2929626D4D000UL, 0x2242600464B4F6B0UL).AsByte();

	private static Vector128<byte> DecryptionSBoxOutputTimes14Table1 => Vector128.Create(0x0C55A6CDFFAAC100UL, 0x9467F36B98593E32UL).AsByte();

	private static Vector128<byte> DecryptionSBoxOutputTable0 => Vector128.Create(0x1387EA537EF94000UL, 0xC7AA6DB9D4943E2DUL).AsByte();

	private static Vector128<byte> DecryptionSBoxOutputTable1 => Vector128.Create(0x12D7560F93441D00UL, 0xCA4B8159D8C58E9CUL).AsByte();

	private static Vector128<byte> EncryptionForwardMixColumnsShuffleMask => Vector128.Create(0x080B0A0904070605UL, 0x000302010C0F0E0DUL).AsByte();

	private static Vector128<byte> EncryptionBackwardMixColumnsShuffleMask => Vector128.Create(0x020100030E0D0C0FUL, 0x0A09080B06050407UL).AsByte();

	private static Vector128<byte> DecryptionForwardMixColumnsShuffleMask => Vector128.Create(0x000302010C0F0E0DUL, 0x080B0A0904070605UL).AsByte();

	private static ReadOnlySpan<byte> ShiftRowsShuffleMasks =>
	[
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
		0x00, 0x05, 0x0A, 0x0F, 0x04, 0x09, 0x0E, 0x03, 0x08, 0x0D, 0x02, 0x07, 0x0C, 0x01, 0x06, 0x0B,
		0x00, 0x09, 0x02, 0x0B, 0x04, 0x0D, 0x06, 0x0F, 0x08, 0x01, 0x0A, 0x03, 0x0C, 0x05, 0x0E, 0x07,
		0x00, 0x0D, 0x0A, 0x07, 0x04, 0x01, 0x0E, 0x0B, 0x08, 0x05, 0x02, 0x0F, 0x0C, 0x09, 0x06, 0x03
	];

	private static Vector128<byte> RotateColumnsBy1 => Vector128.Create(0x0407060500030201UL, 0x0C0F0E0D080B0A09UL).AsByte();

	private static Vector128<byte> RotateColumnsBy2 => Vector128.Create(0x0504070601000302UL, 0x0D0C0F0E09080B0AUL).AsByte();

	private static Vector128<byte> RotateColumnsBy3 => Vector128.Create(0x0605040702010003UL, 0x0E0D0C0F0A09080BUL).AsByte();

	private static Vector128<byte> LowNibbleMask => Vector128.Create((byte)0x0F);

	private static Vector128<byte> SBoxAffineConstant => Vector128.Create((byte)0x63);

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> GetShiftRowsShuffleMask(int rows)
	{
		return Vector128.LoadUnsafe(ref ShiftRowsShuffleMasks.GetReference(), (nuint)((rows & 3) << 4));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> ApplyInputTransform(Vector128<byte> value, Vector128<byte> lowTable, Vector128<byte> highTable)
	{
		Vector128<byte> lowNibble = value & LowNibbleMask;
		Vector128<byte> highNibble = (value.AsUInt32() >>> 4).AsByte() & LowNibbleMask;
		return Ssse3.Shuffle(lowTable, lowNibble) ^ Ssse3.Shuffle(highTable, highNibble);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ComputeInverseIndices(Vector128<byte> state, out Vector128<byte> lookupIndex0, out Vector128<byte> lookupIndex1)
	{
		Vector128<byte> lowNibble = state & LowNibbleMask;
		Vector128<byte> highNibble = (state.AsUInt32() >>> 4).AsByte() & LowNibbleMask;
		Vector128<byte> combinedNibble = lowNibble ^ highNibble;

		Vector128<byte> adjustment = Ssse3.Shuffle(InverseAdjustmentTable, lowNibble);
		Vector128<byte> highInverse = Ssse3.Shuffle(InverseLookupTable, highNibble) ^ adjustment;
		Vector128<byte> combinedInverse = Ssse3.Shuffle(InverseLookupTable, combinedNibble) ^ adjustment;

		lookupIndex0 = Ssse3.Shuffle(InverseLookupTable, highInverse) ^ combinedNibble;
		lookupIndex1 = Ssse3.Shuffle(InverseLookupTable, combinedInverse) ^ highNibble;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> EncryptRound(Vector128<byte> state, Vector128<byte> roundKey, Vector128<byte> forwardShuffle, Vector128<byte> backwardShuffle)
	{
		ComputeInverseIndices(state, out Vector128<byte> lookupIndex0, out Vector128<byte> lookupIndex1);

		Vector128<byte> substituted = Ssse3.Shuffle(SBoxStage1Table0, lookupIndex0) ^ Ssse3.Shuffle(SBoxStage1Table1, lookupIndex1) ^ roundKey;
		Vector128<byte> doubled = Ssse3.Shuffle(SBoxStage2Table0, lookupIndex0) ^ Ssse3.Shuffle(SBoxStage2Table1, lookupIndex1);

		Vector128<byte> forwardMixed = Ssse3.Shuffle(substituted, forwardShuffle) ^ doubled;
		Vector128<byte> backwardMixed = Ssse3.Shuffle(substituted, backwardShuffle) ^ forwardMixed;

		return Ssse3.Shuffle(forwardMixed, forwardShuffle) ^ backwardMixed;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> EncryptFinalRound(Vector128<byte> state, Vector128<byte> roundKey, Vector128<byte> shiftRowsShuffle)
	{
		ComputeInverseIndices(state, out Vector128<byte> lookupIndex0, out Vector128<byte> lookupIndex1);
		return Ssse3.Shuffle(Ssse3.Shuffle(SBoxOutputTable0, lookupIndex0) ^ Ssse3.Shuffle(SBoxOutputTable1, lookupIndex1) ^ roundKey, shiftRowsShuffle);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> DecryptRound(Vector128<byte> state, Vector128<byte> roundKey, Vector128<byte> forwardShuffle)
	{
		ComputeInverseIndices(state, out Vector128<byte> lookupIndex0, out Vector128<byte> lookupIndex1);

		Vector128<byte> mixed = roundKey ^ (Ssse3.Shuffle(DecryptionSBoxOutputTimes9Table0, lookupIndex0) ^ Ssse3.Shuffle(DecryptionSBoxOutputTimes9Table1, lookupIndex1));
		mixed = Ssse3.Shuffle(mixed, forwardShuffle) ^ Ssse3.Shuffle(DecryptionSBoxOutputTimes13Table0, lookupIndex0) ^ Ssse3.Shuffle(DecryptionSBoxOutputTimes13Table1, lookupIndex1);
		mixed = Ssse3.Shuffle(mixed, forwardShuffle) ^ Ssse3.Shuffle(DecryptionSBoxOutputTimes11Table0, lookupIndex0) ^ Ssse3.Shuffle(DecryptionSBoxOutputTimes11Table1, lookupIndex1);
		return Ssse3.Shuffle(mixed, forwardShuffle) ^ (Ssse3.Shuffle(DecryptionSBoxOutputTimes14Table0, lookupIndex0) ^ Ssse3.Shuffle(DecryptionSBoxOutputTimes14Table1, lookupIndex1));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> DecryptFinalRound(Vector128<byte> state, Vector128<byte> roundKey, Vector128<byte> shiftRowsShuffle)
	{
		ComputeInverseIndices(state, out Vector128<byte> lookupIndex0, out Vector128<byte> lookupIndex1);
		return Ssse3.Shuffle(Ssse3.Shuffle(DecryptionSBoxOutputTable0, lookupIndex0) ^ Ssse3.Shuffle(DecryptionSBoxOutputTable1, lookupIndex1) ^ roundKey, shiftRowsShuffle);
	}

	private readonly Vector128<byte> Encrypt(Vector128<byte> block)
	{
		ref readonly Vector128<byte> roundKey = ref _roundKeys[0];
		Vector128<byte> forwardShuffle = EncryptionForwardMixColumnsShuffleMask;
		Vector128<byte> backwardShuffle = EncryptionBackwardMixColumnsShuffleMask;

		Vector128<byte> value = ApplyInputTransform(block, EncryptionInputTransformLow, EncryptionInputTransformHigh) ^ roundKey;

		for (int round = 1; round < _rounds; ++round)
		{
			roundKey = ref Unsafe.Add(ref Unsafe.AsRef(in roundKey), 1);
			value = EncryptRound(value, roundKey, forwardShuffle, backwardShuffle);
			forwardShuffle = Ssse3.AlignRight(forwardShuffle, forwardShuffle, 4);
			backwardShuffle = Ssse3.AlignRight(backwardShuffle, backwardShuffle, 12);
		}

		return EncryptFinalRound(value, Unsafe.Add(ref Unsafe.AsRef(in roundKey), 1), GetShiftRowsShuffleMask(_rounds));
	}

	private readonly void Encrypt2(ref Vector128<byte> block0, ref Vector128<byte> block1)
	{
		ref readonly Vector128<byte> roundKey = ref _roundKeys[0];
		Vector128<byte> forwardShuffle = EncryptionForwardMixColumnsShuffleMask;
		Vector128<byte> backwardShuffle = EncryptionBackwardMixColumnsShuffleMask;

		Vector128<byte> v0 = ApplyInputTransform(block0, EncryptionInputTransformLow, EncryptionInputTransformHigh) ^ roundKey;
		Vector128<byte> v1 = ApplyInputTransform(block1, EncryptionInputTransformLow, EncryptionInputTransformHigh) ^ roundKey;

		for (int round = 1; round < _rounds; ++round)
		{
			roundKey = ref Unsafe.Add(ref Unsafe.AsRef(in roundKey), 1);
			v0 = EncryptRound(v0, roundKey, forwardShuffle, backwardShuffle);
			v1 = EncryptRound(v1, roundKey, forwardShuffle, backwardShuffle);
			forwardShuffle = Ssse3.AlignRight(forwardShuffle, forwardShuffle, 4);
			backwardShuffle = Ssse3.AlignRight(backwardShuffle, backwardShuffle, 12);
		}

		Vector128<byte> finalRoundKey = Unsafe.Add(ref Unsafe.AsRef(in roundKey), 1);
		Vector128<byte> shiftRowsShuffle = GetShiftRowsShuffleMask(_rounds);
		block0 = EncryptFinalRound(v0, finalRoundKey, shiftRowsShuffle);
		block1 = EncryptFinalRound(v1, finalRoundKey, shiftRowsShuffle);
	}

	private readonly void Encrypt3(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2)
	{
		ref readonly Vector128<byte> roundKey = ref _roundKeys[0];
		Vector128<byte> forwardShuffle = EncryptionForwardMixColumnsShuffleMask;
		Vector128<byte> backwardShuffle = EncryptionBackwardMixColumnsShuffleMask;

		v0 = ApplyInputTransform(v0, EncryptionInputTransformLow, EncryptionInputTransformHigh) ^ roundKey;
		v1 = ApplyInputTransform(v1, EncryptionInputTransformLow, EncryptionInputTransformHigh) ^ roundKey;
		v2 = ApplyInputTransform(v2, EncryptionInputTransformLow, EncryptionInputTransformHigh) ^ roundKey;

		for (int round = 1; round < _rounds; ++round)
		{
			roundKey = ref Unsafe.Add(ref Unsafe.AsRef(in roundKey), 1);
			v0 = EncryptRound(v0, roundKey, forwardShuffle, backwardShuffle);
			v1 = EncryptRound(v1, roundKey, forwardShuffle, backwardShuffle);
			v2 = EncryptRound(v2, roundKey, forwardShuffle, backwardShuffle);
			forwardShuffle = Ssse3.AlignRight(forwardShuffle, forwardShuffle, 4);
			backwardShuffle = Ssse3.AlignRight(backwardShuffle, backwardShuffle, 12);
		}

		ref readonly Vector128<byte> finalRoundKey = ref Unsafe.Add(ref Unsafe.AsRef(in roundKey), 1);
		Vector128<byte> shiftRowsShuffle = GetShiftRowsShuffleMask(_rounds);
		v0 = EncryptFinalRound(v0, finalRoundKey, shiftRowsShuffle);
		v1 = EncryptFinalRound(v1, finalRoundKey, shiftRowsShuffle);
		v2 = EncryptFinalRound(v2, finalRoundKey, shiftRowsShuffle);
	}

	private readonly void Encrypt4(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3)
	{
		ref readonly Vector128<byte> roundKey = ref _roundKeys[0];
		Vector128<byte> forwardShuffle = EncryptionForwardMixColumnsShuffleMask;
		Vector128<byte> backwardShuffle = EncryptionBackwardMixColumnsShuffleMask;

		v0 = ApplyInputTransform(v0, EncryptionInputTransformLow, EncryptionInputTransformHigh) ^ roundKey;
		v1 = ApplyInputTransform(v1, EncryptionInputTransformLow, EncryptionInputTransformHigh) ^ roundKey;
		v2 = ApplyInputTransform(v2, EncryptionInputTransformLow, EncryptionInputTransformHigh) ^ roundKey;
		v3 = ApplyInputTransform(v3, EncryptionInputTransformLow, EncryptionInputTransformHigh) ^ roundKey;

		for (int round = 1; round < _rounds; ++round)
		{
			roundKey = ref Unsafe.Add(ref Unsafe.AsRef(in roundKey), 1);
			v0 = EncryptRound(v0, roundKey, forwardShuffle, backwardShuffle);
			v1 = EncryptRound(v1, roundKey, forwardShuffle, backwardShuffle);
			v2 = EncryptRound(v2, roundKey, forwardShuffle, backwardShuffle);
			v3 = EncryptRound(v3, roundKey, forwardShuffle, backwardShuffle);
			forwardShuffle = Ssse3.AlignRight(forwardShuffle, forwardShuffle, 4);
			backwardShuffle = Ssse3.AlignRight(backwardShuffle, backwardShuffle, 12);
		}

		ref readonly Vector128<byte> finalRoundKey = ref Unsafe.Add(ref Unsafe.AsRef(in roundKey), 1);
		Vector128<byte> shiftRowsShuffle = GetShiftRowsShuffleMask(_rounds);
		v0 = EncryptFinalRound(v0, finalRoundKey, shiftRowsShuffle);
		v1 = EncryptFinalRound(v1, finalRoundKey, shiftRowsShuffle);
		v2 = EncryptFinalRound(v2, finalRoundKey, shiftRowsShuffle);
		v3 = EncryptFinalRound(v3, finalRoundKey, shiftRowsShuffle);
	}

	private readonly Vector128<byte> Decrypt(Vector128<byte> block)
	{
		ref readonly Vector128<byte> roundKey = ref _reverseRoundKeys[0];
		Vector128<byte> forwardShuffle = DecryptionForwardMixColumnsShuffleMask;

		Vector128<byte> value = ApplyInputTransform(block, DecryptionInputTransformLow, DecryptionInputTransformHigh) ^ roundKey;

		for (int round = 1; round < _rounds; ++round)
		{
			roundKey = ref Unsafe.Add(ref Unsafe.AsRef(in roundKey), 1);
			value = DecryptRound(value, roundKey, forwardShuffle);
			forwardShuffle = Ssse3.AlignRight(forwardShuffle, forwardShuffle, 12);
		}

		return DecryptFinalRound(value, Unsafe.Add(ref Unsafe.AsRef(in roundKey), 1), GetShiftRowsShuffleMask(-_rounds));
	}

	private readonly void Decrypt2(ref Vector128<byte> block0, ref Vector128<byte> block1)
	{
		ref readonly Vector128<byte> roundKey = ref _reverseRoundKeys[0];
		Vector128<byte> forwardShuffle = DecryptionForwardMixColumnsShuffleMask;

		Vector128<byte> v0 = ApplyInputTransform(block0, DecryptionInputTransformLow, DecryptionInputTransformHigh) ^ roundKey;
		Vector128<byte> v1 = ApplyInputTransform(block1, DecryptionInputTransformLow, DecryptionInputTransformHigh) ^ roundKey;

		for (int round = 1; round < _rounds; ++round)
		{
			roundKey = ref Unsafe.Add(ref Unsafe.AsRef(in roundKey), 1);
			v0 = DecryptRound(v0, roundKey, forwardShuffle);
			v1 = DecryptRound(v1, roundKey, forwardShuffle);
			forwardShuffle = Ssse3.AlignRight(forwardShuffle, forwardShuffle, 12);
		}

		Vector128<byte> finalRoundKey = Unsafe.Add(ref Unsafe.AsRef(in roundKey), 1);
		Vector128<byte> shiftRowsShuffle = GetShiftRowsShuffleMask(-_rounds);
		block0 = DecryptFinalRound(v0, finalRoundKey, shiftRowsShuffle);
		block1 = DecryptFinalRound(v1, finalRoundKey, shiftRowsShuffle);
	}

	private readonly void Decrypt3(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2)
	{
		ref readonly Vector128<byte> roundKey = ref _reverseRoundKeys[0];
		Vector128<byte> forwardShuffle = DecryptionForwardMixColumnsShuffleMask;

		v0 = ApplyInputTransform(v0, DecryptionInputTransformLow, DecryptionInputTransformHigh) ^ roundKey;
		v1 = ApplyInputTransform(v1, DecryptionInputTransformLow, DecryptionInputTransformHigh) ^ roundKey;
		v2 = ApplyInputTransform(v2, DecryptionInputTransformLow, DecryptionInputTransformHigh) ^ roundKey;

		for (int round = 1; round < _rounds; ++round)
		{
			roundKey = ref Unsafe.Add(ref Unsafe.AsRef(in roundKey), 1);
			v0 = DecryptRound(v0, roundKey, forwardShuffle);
			v1 = DecryptRound(v1, roundKey, forwardShuffle);
			v2 = DecryptRound(v2, roundKey, forwardShuffle);
			forwardShuffle = Ssse3.AlignRight(forwardShuffle, forwardShuffle, 12);
		}

		ref readonly Vector128<byte> finalRoundKey = ref Unsafe.Add(ref Unsafe.AsRef(in roundKey), 1);
		Vector128<byte> shiftRowsShuffle = GetShiftRowsShuffleMask(-_rounds);
		v0 = DecryptFinalRound(v0, finalRoundKey, shiftRowsShuffle);
		v1 = DecryptFinalRound(v1, finalRoundKey, shiftRowsShuffle);
		v2 = DecryptFinalRound(v2, finalRoundKey, shiftRowsShuffle);
	}

	private readonly void Decrypt4(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3)
	{
		ref readonly Vector128<byte> roundKey = ref _reverseRoundKeys[0];
		Vector128<byte> forwardShuffle = DecryptionForwardMixColumnsShuffleMask;

		v0 = ApplyInputTransform(v0, DecryptionInputTransformLow, DecryptionInputTransformHigh) ^ roundKey;
		v1 = ApplyInputTransform(v1, DecryptionInputTransformLow, DecryptionInputTransformHigh) ^ roundKey;
		v2 = ApplyInputTransform(v2, DecryptionInputTransformLow, DecryptionInputTransformHigh) ^ roundKey;
		v3 = ApplyInputTransform(v3, DecryptionInputTransformLow, DecryptionInputTransformHigh) ^ roundKey;

		for (int round = 1; round < _rounds; ++round)
		{
			roundKey = ref Unsafe.Add(ref Unsafe.AsRef(in roundKey), 1);
			v0 = DecryptRound(v0, roundKey, forwardShuffle);
			v1 = DecryptRound(v1, roundKey, forwardShuffle);
			v2 = DecryptRound(v2, roundKey, forwardShuffle);
			v3 = DecryptRound(v3, roundKey, forwardShuffle);
			forwardShuffle = Ssse3.AlignRight(forwardShuffle, forwardShuffle, 12);
		}

		ref readonly Vector128<byte> finalRoundKey = ref Unsafe.Add(ref Unsafe.AsRef(in roundKey), 1);
		Vector128<byte> shiftRowsShuffle = GetShiftRowsShuffleMask(-_rounds);
		v0 = DecryptFinalRound(v0, finalRoundKey, shiftRowsShuffle);
		v1 = DecryptFinalRound(v1, finalRoundKey, shiftRowsShuffle);
		v2 = DecryptFinalRound(v2, finalRoundKey, shiftRowsShuffle);
		v3 = DecryptFinalRound(v3, finalRoundKey, shiftRowsShuffle);
	}

	private static Vector128<byte> SubstituteBytes(Vector128<byte> value)
	{
		ComputeInverseIndices(ApplyInputTransform(value, EncryptionInputTransformLow, EncryptionInputTransformHigh), out Vector128<byte> lookupIndex0, out Vector128<byte> lookupIndex1);
		return Ssse3.Shuffle(SBoxOutputTable0, lookupIndex0) ^ Ssse3.Shuffle(SBoxOutputTable1, lookupIndex1) ^ SBoxAffineConstant;
	}

	private static uint SubstituteWord(uint value)
	{
		return SubstituteBytes(Vector128.Create(value).AsByte()).AsUInt32().GetElement(0);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> MultiplyByX(Vector128<byte> value)
	{
		Vector128<byte> doubled = (value.AsUInt64() << 1).AsByte() & Vector128.Create((byte)0xFE);
		Vector128<byte> carry = Vector128.LessThan(value.AsSByte(), Vector128<sbyte>.Zero).AsByte();
		return doubled ^ (carry & Vector128.Create((byte)0x1B));
	}

	private static Vector128<byte> InverseMixColumns(Vector128<byte> value)
	{
		Vector128<byte> times2 = MultiplyByX(value);
		Vector128<byte> times4 = MultiplyByX(times2);
		Vector128<byte> times8 = MultiplyByX(times4);

		Vector128<byte> times14 = times8 ^ times4 ^ times2;
		Vector128<byte> times11 = times8 ^ times2 ^ value;
		Vector128<byte> times13 = times8 ^ times4 ^ value;
		Vector128<byte> times9 = times8 ^ value;

		return times14
				^ Ssse3.Shuffle(times11, RotateColumnsBy1)
				^ Ssse3.Shuffle(times13, RotateColumnsBy2)
				^ Ssse3.Shuffle(times9, RotateColumnsBy3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> InverseKeyMixColumns(Vector128<byte> value)
	{
		return Ssse3.Shuffle(value, RotateColumnsBy1) ^ Ssse3.Shuffle(value, RotateColumnsBy2) ^ Ssse3.Shuffle(value, RotateColumnsBy3);
	}

	private AesCipherVpaes(ReadOnlySpan<byte> key)
	{
		_rounds = key.Length switch
		{
			16 => 10,
			24 => 12,
			32 => 14,
			_ => ThrowHelper.ThrowArgumentOutOfRangeException<int>(nameof(key), "Key length must be 16/24/32 bytes")
		};

		Span<uint> words = stackalloc uint[60];
		int nk = key.Length / sizeof(uint);
		int wordCount = (_rounds + 1) * 4;

		for (int i = 0; i < nk; ++i)
		{
			words[i] = BinaryPrimitives.ReadUInt32LittleEndian(key.Slice(i * sizeof(uint)));
		}

		for (int i = nk; i < wordCount; ++i)
		{
			uint t = words[i - 1];

			if (i % nk is 0)
			{
				t = SubstituteWord(t).RotateRight(8) ^ AesCipher.Rcon[i / nk];
			}
			else if (nk is 8 && i % nk is 4)
			{
				t = SubstituteWord(t);
			}

			words[i] = words[i - nk] ^ t;
		}

		ref uint wordRef = ref words.GetReference();

		// Round 0 is added straight after the input transform, so it only needs the basis change.
		_roundKeys[0] = ApplyInputTransform(Vector128.LoadUnsafe(ref wordRef).AsByte(), EncryptionInputTransformLow, EncryptionInputTransformHigh);
		_reverseRoundKeys[_rounds] = Ssse3.Shuffle(Vector128.LoadUnsafe(ref wordRef).AsByte(), GetShiftRowsShuffleMask(_rounds));

		for (int round = 1; round < _rounds; ++round)
		{
			Vector128<byte> roundKey = Vector128.LoadUnsafe(ref wordRef, (nuint)(round * 4)).AsByte() ^ SBoxAffineConstant;

			_roundKeys[round] = ApplyInputTransform(Ssse3.Shuffle(InverseKeyMixColumns(roundKey), GetShiftRowsShuffleMask(-round)), EncryptionInputTransformLow, EncryptionInputTransformHigh);
			_reverseRoundKeys[_rounds - round] = ApplyInputTransform
			(
				Ssse3.Shuffle(Ssse3.Shuffle(InverseMixColumns(roundKey), RotateColumnsBy1), GetShiftRowsShuffleMask(_rounds - round)),
				DecryptionInputTransformLow,
				DecryptionInputTransformHigh
			);
		}

		Vector128<byte> finalRoundKey = Vector128.LoadUnsafe(ref wordRef, (nuint)(_rounds * 4)).AsByte();
		_roundKeys[_rounds] = Ssse3.Shuffle(finalRoundKey, GetShiftRowsShuffleMask(-_rounds)) ^ SBoxAffineConstant;
		_reverseRoundKeys[0] = ApplyInputTransform(finalRoundKey ^ SBoxAffineConstant, DecryptionInputTransformLow, DecryptionInputTransformHigh);

		words.ZeroMemory();
	}

	public static AesCipherVpaes Create(ReadOnlySpan<byte> key)
	{
		return new AesCipherVpaes(key);
	}

	public void Dispose()
	{
		_roundKeys.ZeroMemory();
		_reverseRoundKeys.ZeroMemory();
	}

	public readonly void EncryptBlocks(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ref byte src = ref source.GetReference();
		ref byte dst = ref destination.GetReference();
		int offset = 0;

		while (source.Length - offset >= 64)
		{
			Vector128<byte> v0 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 0));
			Vector128<byte> v1 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 16));
			Vector128<byte> v2 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 32));
			Vector128<byte> v3 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 48));

			Encrypt4(ref v0, ref v1, ref v2, ref v3);

			v0.StoreUnsafe(ref dst, (nuint)(offset + 0));
			v1.StoreUnsafe(ref dst, (nuint)(offset + 16));
			v2.StoreUnsafe(ref dst, (nuint)(offset + 32));
			v3.StoreUnsafe(ref dst, (nuint)(offset + 48));
			offset += 64;
		}

		if (source.Length - offset >= 48)
		{
			Vector128<byte> v0 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 0));
			Vector128<byte> v1 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 16));
			Vector128<byte> v2 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 32));

			Encrypt3(ref v0, ref v1, ref v2);

			v0.StoreUnsafe(ref dst, (nuint)(offset + 0));
			v1.StoreUnsafe(ref dst, (nuint)(offset + 16));
			v2.StoreUnsafe(ref dst, (nuint)(offset + 32));
			return;
		}

		if (source.Length - offset >= 32)
		{
			Vector128<byte> v0 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 0));
			Vector128<byte> v1 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 16));

			Encrypt2(ref v0, ref v1);

			v0.StoreUnsafe(ref dst, (nuint)(offset + 0));
			v1.StoreUnsafe(ref dst, (nuint)(offset + 16));
			offset += 32;
		}

		if (offset < source.Length)
		{
			Encrypt(Vector128.LoadUnsafe(ref src, (nuint)offset)).StoreUnsafe(ref dst, (nuint)offset);
		}
	}

	public readonly void DecryptBlocks(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ref byte src = ref source.GetReference();
		ref byte dst = ref destination.GetReference();
		int offset = 0;

		while (source.Length - offset >= 64)
		{
			Vector128<byte> v0 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 0));
			Vector128<byte> v1 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 16));
			Vector128<byte> v2 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 32));
			Vector128<byte> v3 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 48));

			Decrypt4(ref v0, ref v1, ref v2, ref v3);

			v0.StoreUnsafe(ref dst, (nuint)(offset + 0));
			v1.StoreUnsafe(ref dst, (nuint)(offset + 16));
			v2.StoreUnsafe(ref dst, (nuint)(offset + 32));
			v3.StoreUnsafe(ref dst, (nuint)(offset + 48));
			offset += 64;
		}

		if (source.Length - offset >= 48)
		{
			Vector128<byte> v0 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 0));
			Vector128<byte> v1 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 16));
			Vector128<byte> v2 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 32));

			Decrypt3(ref v0, ref v1, ref v2);

			v0.StoreUnsafe(ref dst, (nuint)(offset + 0));
			v1.StoreUnsafe(ref dst, (nuint)(offset + 16));
			v2.StoreUnsafe(ref dst, (nuint)(offset + 32));
			return;
		}

		if (source.Length - offset >= 32)
		{
			Vector128<byte> v0 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 0));
			Vector128<byte> v1 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 16));

			Decrypt2(ref v0, ref v1);

			v0.StoreUnsafe(ref dst, (nuint)(offset + 0));
			v1.StoreUnsafe(ref dst, (nuint)(offset + 16));
			offset += 32;
		}

		if (offset < source.Length)
		{
			Decrypt(Vector128.LoadUnsafe(ref src, (nuint)offset)).StoreUnsafe(ref dst, (nuint)offset);
		}
	}

	// Fuses the mode's XOR with AES to avoid intermediate ciphertext/keystream stores.
	public readonly void TransformWithMask(ReadOnlySpan<byte> source, ReadOnlySpan<byte> mask, Span<byte> destination, bool decrypt, bool xorInput)
	{
		ref byte src = ref source.GetReference();
		ref byte xor = ref mask.GetReference();
		ref byte dst = ref destination.GetReference();
		int offset = 0;

		while (source.Length - offset >= 64)
		{
			Vector128<byte> v0 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 0));
			Vector128<byte> v1 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 16));
			Vector128<byte> v2 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 32));
			Vector128<byte> v3 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 48));

			if (xorInput)
			{
				v0 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 0));
				v1 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 16));
				v2 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 32));
				v3 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 48));
			}

			if (decrypt)
			{
				Decrypt4(ref v0, ref v1, ref v2, ref v3);
			}
			else
			{
				Encrypt4(ref v0, ref v1, ref v2, ref v3);
			}

			(v0 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 0))).StoreUnsafe(ref dst, (nuint)(offset + 0));
			(v1 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 16))).StoreUnsafe(ref dst, (nuint)(offset + 16));
			(v2 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 32))).StoreUnsafe(ref dst, (nuint)(offset + 32));
			(v3 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 48))).StoreUnsafe(ref dst, (nuint)(offset + 48));
			offset += 64;
		}

		if (source.Length - offset >= 48)
		{
			Vector128<byte> v0 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 0));
			Vector128<byte> v1 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 16));
			Vector128<byte> v2 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 32));

			if (xorInput)
			{
				v0 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 0));
				v1 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 16));
				v2 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 32));
			}

			if (decrypt)
			{
				Decrypt3(ref v0, ref v1, ref v2);
			}
			else
			{
				Encrypt3(ref v0, ref v1, ref v2);
			}

			(v0 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 0))).StoreUnsafe(ref dst, (nuint)(offset + 0));
			(v1 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 16))).StoreUnsafe(ref dst, (nuint)(offset + 16));
			(v2 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 32))).StoreUnsafe(ref dst, (nuint)(offset + 32));
			return;
		}

		if (source.Length - offset >= 32)
		{
			Vector128<byte> v0 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 0));
			Vector128<byte> v1 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 16));

			if (xorInput)
			{
				v0 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 0));
				v1 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 16));
			}

			if (decrypt)
			{
				Decrypt2(ref v0, ref v1);
			}
			else
			{
				Encrypt2(ref v0, ref v1);
			}

			(v0 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 0))).StoreUnsafe(ref dst, (nuint)(offset + 0));
			(v1 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 16))).StoreUnsafe(ref dst, (nuint)(offset + 16));
			offset += 32;
		}

		if (offset < source.Length)
		{
			Vector128<byte> blockMask = Vector128.LoadUnsafe(ref xor, (nuint)offset);
			Vector128<byte> value = Vector128.LoadUnsafe(ref src, (nuint)offset);

			if (xorInput)
			{
				value ^= blockMask;
			}

			value = decrypt ? Decrypt(value) : Encrypt(value);
			(value ^ blockMask).StoreUnsafe(ref dst, (nuint)offset);
		}
	}
}
