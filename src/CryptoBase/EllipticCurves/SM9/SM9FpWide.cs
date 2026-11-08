namespace CryptoBase.EllipticCurves.SM9;

// A sum of products for one Montgomery reduction, Σ T_k·2^(52k) in ten columns that wrap modulo 2^64 and read as signed: SM9Fp.Reduce takes columns below 2^62 in magnitude whose value is not negative. Columns are added and subtracted without carries.
internal struct SM9FpWide
{
	internal ulong T0;
	internal ulong T1;
	internal ulong T2;
	internal ulong T3;
	internal ulong T4;
	internal ulong T5;
	internal ulong T6;
	internal ulong T7;
	internal ulong T8;
	internal ulong T9;

	// 128p² in its ten canonical columns, each below 2^52, the offset of SM9Fp.ReduceWide.
	private const ulong Offset0 = 0x00028F5CFB4F8480;
	private const ulong Offset1 = 0x000785A9512AD93E;
	private const ulong Offset2 = 0x00061961FE81F6FC;
	private const ulong Offset3 = 0x0001A9250C20F559;
	private const ulong Offset4 = 0x00091684E427DF89;
	private const ulong Offset5 = 0x00008B99BA6F8FF6;
	private const ulong Offset6 = 0x000FF60A2401E81D;
	private const ulong Offset7 = 0x000A7740A5F3E998;
	private const ulong Offset8 = 0x000199AA9F985292;
	private const ulong Offset9 = 0x00040DF880001E10;

	// 11p² in its ten canonical columns, each below 2^52.
	private const ulong ElevenPSquared0 = 0x00057851FD98D563;
	private const ulong ElevenPSquared1 = 0x000B257C8CF9AEAB;
	private const ulong ElevenPSquared2 = 0x000AE62E6BDF2B39;
	private const ulong ElevenPSquared3 = 0x000C84892F0AD515;
	private const ulong ElevenPSquared4 = 0x000307EF6B9B6D35;
	private const ulong ElevenPSquared5 = 0x0007EBFF3605965F;
	private const ulong ElevenPSquared6 = 0x00025F24DF1829F2;
	private const ulong ElevenPSquared7 = 0x0009A63F8E42F613;
	private const ulong ElevenPSquared8 = 0x00062334A9B71718;
	private const ulong ElevenPSquared9 = 0x000059335B000295;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Add(in SM9FpWide left, in SM9FpWide right, out SM9FpWide result)
	{
		result.T0 = left.T0 + right.T0;
		result.T1 = left.T1 + right.T1;
		result.T2 = left.T2 + right.T2;
		result.T3 = left.T3 + right.T3;
		result.T4 = left.T4 + right.T4;
		result.T5 = left.T5 + right.T5;
		result.T6 = left.T6 + right.T6;
		result.T7 = left.T7 + right.T7;
		result.T8 = left.T8 + right.T8;
		result.T9 = left.T9 + right.T9;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Subtract(in SM9FpWide left, in SM9FpWide right, out SM9FpWide result)
	{
		result.T0 = left.T0 - right.T0;
		result.T1 = left.T1 - right.T1;
		result.T2 = left.T2 - right.T2;
		result.T3 = left.T3 - right.T3;
		result.T4 = left.T4 - right.T4;
		result.T5 = left.T5 - right.T5;
		result.T6 = left.T6 - right.T6;
		result.T7 = left.T7 - right.T7;
		result.T8 = left.T8 - right.T8;
		result.T9 = left.T9 - right.T9;
	}

	// left − 2·right + 11p², whose value is not negative for a right below 5.5p², as the product of two reduced elements is.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void SubtractTwice(in SM9FpWide left, in SM9FpWide right, out SM9FpWide result)
	{
		result.T0 = left.T0 - 2 * right.T0 + ElevenPSquared0;
		result.T1 = left.T1 - 2 * right.T1 + ElevenPSquared1;
		result.T2 = left.T2 - 2 * right.T2 + ElevenPSquared2;
		result.T3 = left.T3 - 2 * right.T3 + ElevenPSquared3;
		result.T4 = left.T4 - 2 * right.T4 + ElevenPSquared4;
		result.T5 = left.T5 - 2 * right.T5 + ElevenPSquared5;
		result.T6 = left.T6 - 2 * right.T6 + ElevenPSquared6;
		result.T7 = left.T7 - 2 * right.T7 + ElevenPSquared7;
		result.T8 = left.T8 - 2 * right.T8 + ElevenPSquared8;
		result.T9 = left.T9 - 2 * right.T9 + ElevenPSquared9;
	}

	// left − 2·right, without an offset.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void SubtractTwiceUnbalanced(in SM9FpWide left, in SM9FpWide right, out SM9FpWide result)
	{
		result.T0 = left.T0 - 2 * right.T0;
		result.T1 = left.T1 - 2 * right.T1;
		result.T2 = left.T2 - 2 * right.T2;
		result.T3 = left.T3 - 2 * right.T3;
		result.T4 = left.T4 - 2 * right.T4;
		result.T5 = left.T5 - 2 * right.T5;
		result.T6 = left.T6 - 2 * right.T6;
		result.T7 = left.T7 - 2 * right.T7;
		result.T8 = left.T8 - 2 * right.T8;
		result.T9 = left.T9 - 2 * right.T9;
	}

	// value + 128p².
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void AddOffset(in SM9FpWide value, out SM9FpWide result)
	{
		result.T0 = value.T0 + Offset0;
		result.T1 = value.T1 + Offset1;
		result.T2 = value.T2 + Offset2;
		result.T3 = value.T3 + Offset3;
		result.T4 = value.T4 + Offset4;
		result.T5 = value.T5 + Offset5;
		result.T6 = value.T6 + Offset6;
		result.T7 = value.T7 + Offset7;
		result.T8 = value.T8 + Offset8;
		result.T9 = value.T9 + Offset9;
	}

	// Carries every column but the top one into the next, arithmetically: the value stays, columns 0 to 8 end in [0, 2^52) and column 9 takes the rest, so that sums of a few such values stay far within the columns that SM9Fp.Reduce takes.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Normalize(ref SM9FpWide value)
	{
		const ulong mask = (1UL << 52) - 1;
		value.T1 += (ulong)((long)value.T0 >> 52);
		value.T0 &= mask;
		value.T2 += (ulong)((long)value.T1 >> 52);
		value.T1 &= mask;
		value.T3 += (ulong)((long)value.T2 >> 52);
		value.T2 &= mask;
		value.T4 += (ulong)((long)value.T3 >> 52);
		value.T3 &= mask;
		value.T5 += (ulong)((long)value.T4 >> 52);
		value.T4 &= mask;
		value.T6 += (ulong)((long)value.T5 >> 52);
		value.T5 &= mask;
		value.T7 += (ulong)((long)value.T6 >> 52);
		value.T6 &= mask;
		value.T8 += (ulong)((long)value.T7 >> 52);
		value.T7 &= mask;
		value.T9 += (ulong)((long)value.T8 >> 52);
		value.T8 &= mask;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void MultiplySmall(in SM9FpWide value, ulong k, out SM9FpWide result)
	{
		result.T0 = value.T0 * k;
		result.T1 = value.T1 * k;
		result.T2 = value.T2 * k;
		result.T3 = value.T3 * k;
		result.T4 = value.T4 * k;
		result.T5 = value.T5 * k;
		result.T6 = value.T6 * k;
		result.T7 = value.T7 * k;
		result.T8 = value.T8 * k;
		result.T9 = value.T9 * k;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void SubtractMultiple(in SM9FpWide left, in SM9FpWide right, ulong k, out SM9FpWide result)
	{
		result.T0 = left.T0 - right.T0 * k;
		result.T1 = left.T1 - right.T1 * k;
		result.T2 = left.T2 - right.T2 * k;
		result.T3 = left.T3 - right.T3 * k;
		result.T4 = left.T4 - right.T4 * k;
		result.T5 = left.T5 - right.T5 * k;
		result.T6 = left.T6 - right.T6 * k;
		result.T7 = left.T7 - right.T7 * k;
		result.T8 = left.T8 - right.T8 * k;
		result.T9 = left.T9 - right.T9 * k;
	}

	// value + x·2^260 for x of limbs below 2^62, into columns 5 to 9: the reduction of the sum is that of value plus x, as Montgomery form takes R = 2^260.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void AddShifted(ref SM9FpWide value, in SM9Fp x)
	{
		value.T5 += x.L0;
		value.T6 += x.L1;
		value.T7 += x.L2;
		value.T8 += x.L3;
		value.T9 += x.L4;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void AddTwice(in SM9FpWide left, in SM9FpWide right, out SM9FpWide result)
	{
		result.T0 = left.T0 + 2 * right.T0;
		result.T1 = left.T1 + 2 * right.T1;
		result.T2 = left.T2 + 2 * right.T2;
		result.T3 = left.T3 + 2 * right.T3;
		result.T4 = left.T4 + 2 * right.T4;
		result.T5 = left.T5 + 2 * right.T5;
		result.T6 = left.T6 + 2 * right.T6;
		result.T7 = left.T7 + 2 * right.T7;
		result.T8 = left.T8 + 2 * right.T8;
		result.T9 = left.T9 + 2 * right.T9;
	}
}
