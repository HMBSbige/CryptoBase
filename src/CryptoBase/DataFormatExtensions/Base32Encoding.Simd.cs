namespace CryptoBase.DataFormatExtensions;

public sealed partial class Base32Encoding
{
	private const byte CustomAlphabetKind = 0;
	private const byte Rfc4648AlphabetKind = 1;
	private const byte Rfc4648HexAlphabetKind = 2;
	private const int Arm64EncodeSimdThreshold = 20;
	private const int Arm64DecodeSimdThreshold = 16;
	private const int X86EncodeVbmiVl128Threshold = 10;
	private const int X86EncodeCharsSimdThreshold = 20;
	private const int X86EncodeVector256Threshold = 20;
	private const int X86EncodeVector512Threshold = 40;
	private const int X86EncodeAvx512BwThreshold = 160;
	private const int X86DecodeVector128Threshold = 16;
	private const int X86DecodeVector256Threshold = 32;
	private const int X86DecodeVector512Threshold = 64;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void GetEncodeMap(byte alphabetKind, out byte threshold, out byte first, out byte second)
	{
		if (alphabetKind is Rfc4648HexAlphabetKind)
		{
			threshold = 9;
			first = (byte)'0';
			second = 'A' - 10;
		}
		else
		{
			threshold = 25;
			first = (byte)'A';
			second = '2' - 26;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> MapSymbols(Vector128<byte> value, Vector128<sbyte> threshold, Vector128<byte> first, Vector128<byte> second)
	{
		Vector128<byte> mask = Vector128.GreaterThan(value.AsSByte(), threshold).AsByte();
		return value + Vector128.ConditionalSelect(mask, second, first);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreEncodedChars(Vector128<byte> value, ref char destination)
	{
		ref ushort destinationReference = ref Unsafe.As<char, ushort>(ref destination);
		Vector128.WidenLower(value).StoreUnsafe(ref destinationReference);
		Vector128.WidenUpper(value).StoreUnsafe(ref destinationReference, 8);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreEncodedChars(Vector256<byte> value, ref char destination)
	{
		ref ushort destinationReference = ref Unsafe.As<char, ushort>(ref destination);
		Vector256.WidenLower(value).StoreUnsafe(ref destinationReference);
		Vector256.WidenUpper(value).StoreUnsafe(ref destinationReference, 16);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreEncodedChars(Vector512<byte> value, ref char destination)
	{
		ref ushort destinationReference = ref Unsafe.As<char, ushort>(ref destination);
		Vector512.WidenLower(value).StoreUnsafe(ref destinationReference);
		Vector512.WidenUpper(value).StoreUnsafe(ref destinationReference, 32);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool TryNarrowAscii(ref char source, out Vector128<byte> value)
	{
		ref ushort sourceReference = ref Unsafe.As<char, ushort>(ref source);
		Vector128<ushort> lower = Vector128.LoadUnsafe(ref sourceReference);
		Vector128<ushort> upper = Vector128.LoadUnsafe(ref sourceReference, 8);

		if (!Vector128.EqualsAll((lower | upper) & Vector128.Create((ushort)0xff80), Vector128<ushort>.Zero))
		{
			value = default;
			return false;
		}

		value = Vector128.Narrow(lower, upper);
		return true;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool TryNarrowAscii(ref char source, out Vector256<byte> value)
	{
		ref ushort sourceReference = ref Unsafe.As<char, ushort>(ref source);
		Vector256<ushort> lower = Vector256.LoadUnsafe(ref sourceReference);
		Vector256<ushort> upper = Vector256.LoadUnsafe(ref sourceReference, 16);

		if (!Vector256.EqualsAll((lower | upper) & Vector256.Create((ushort)0xff80), Vector256<ushort>.Zero))
		{
			value = default;
			return false;
		}

		value = Vector256.Narrow(lower, upper);
		return true;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool TryNarrowAscii(ref char source, out Vector512<byte> value)
	{
		ref ushort sourceReference = ref Unsafe.As<char, ushort>(ref source);
		Vector512<ushort> lower = Vector512.LoadUnsafe(ref sourceReference);
		Vector512<ushort> upper = Vector512.LoadUnsafe(ref sourceReference, 32);

		if (!Vector512.EqualsAll((lower | upper) & Vector512.Create((ushort)0xff80), Vector512<ushort>.Zero))
		{
			value = default;
			return false;
		}

		value = Vector512.Narrow(lower, upper);
		return true;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool IsAvx512VbmiSupported()
	{
		return Avx512Vbmi.IsSupported && Avx512BW.IsSupported;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool IsAvx512VbmiVlSupported()
	{
		return Avx512Vbmi.VL.IsSupported && Avx512BW.VL.IsSupported;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> PackTwoFast(ref byte source)
	{
		ulong first = Unsafe.ReadUnaligned<ulong>(ref source);
		ulong second = Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref source, 5));
		return Vector128.Create(BinaryPrimitives.ReverseEndianness(first) >> 24, BinaryPrimitives.ReverseEndianness(second) >> 24);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<ulong> PackTwo(ref byte source)
	{
		return Vector128.Create(Pack5(ref source), Pack5(ref Unsafe.Add(ref source, 5)));
	}

	// Keep the offsets in the AdvSimd call chain. On .NET 10 ARM64, forwarding the
	// caller's zero-valued registers is faster than materializing two zero arguments.
	private static int EncodeCharsAdvSimdAuto(ReadOnlySpan<byte> source, Span<char> destination, int sourceOffset, int destinationOffset, byte alphabetKind)
	{
		int sourceRemaining = Math.Min(source.Length - sourceOffset, (destination.Length - destinationOffset) / OutputSymbolsPerBlock * InputBytesPerBlock);
		return sourceRemaining >= Arm64EncodeSimdThreshold
			? EncodeCharsAdvSimd(source, destination, sourceOffset, destinationOffset, alphabetKind)
			: 0;
	}

	private static int EncodeCharsAuto(ReadOnlySpan<byte> source, Span<char> destination, byte alphabetKind)
	{
		int sourceRemaining = Math.Min(source.Length, destination.Length / OutputSymbolsPerBlock * InputBytesPerBlock);

		if (IsAvx512VbmiVlSupported())
		{
			if (sourceRemaining >= X86EncodeVector512Threshold && IsAvx512VbmiSupported())
			{
				return EncodeCharsAvx512Vbmi(source, destination, alphabetKind);
			}

			if (sourceRemaining >= X86EncodeVector256Threshold)
			{
				return EncodeCharsAvx512VbmiVl256(source, destination, alphabetKind);
			}

			return sourceRemaining >= X86EncodeVbmiVl128Threshold
				? EncodeCharsAvx512VbmiVl128Single(source, destination, alphabetKind)
				: 0;
		}

		if (sourceRemaining >= X86EncodeVector512Threshold && IsAvx512VbmiSupported())
		{
			return EncodeCharsAvx512Vbmi(source, destination, alphabetKind);
		}

		if (sourceRemaining >= X86EncodeAvx512BwThreshold && Avx512BW.IsSupported)
		{
			return EncodeCharsAvx512Bw(source, destination, alphabetKind);
		}

		if (sourceRemaining >= X86EncodeVector256Threshold && Avx2.IsSupported)
		{
			return EncodeCharsAvx2(source, destination, alphabetKind);
		}

		return sourceRemaining >= X86EncodeVector256Threshold && Ssse3.IsSupported
			? EncodeCharsSsse3(source, destination, alphabetKind)
			: 0;
	}

	private int EncodeCharsCustomAuto(ReadOnlySpan<byte> source, Span<char> destination)
	{
		int sourceRemaining = Math.Min(source.Length, destination.Length / OutputSymbolsPerBlock * InputBytesPerBlock);

		if (sourceRemaining >= X86EncodeVector512Threshold && IsAvx512VbmiSupported())
		{
			return EncodeCharsAvx512VbmiCustom(source, destination);
		}

		return sourceRemaining >= X86EncodeVector256Threshold && IsAvx512VbmiVlSupported()
			? EncodeCharsAvx512VbmiVl256Custom(source, destination)
			: 0;
	}

	private static int EncodeCharsForced(ReadOnlySpan<byte> source, Span<char> destination, byte alphabetKind, Base32SimdPath path)
	{
		if (path is Base32SimdPath.Scalar || alphabetKind is CustomAlphabetKind)
		{
			return 0;
		}

		return path switch
		{
			Base32SimdPath.AdvSimd when AdvSimd.IsSupported => EncodeCharsAdvSimd(source, destination, 0, 0, alphabetKind),
			Base32SimdPath.Avx512Vbmi when IsAvx512VbmiSupported() => EncodeCharsAvx512Vbmi(source, destination, alphabetKind),
			Base32SimdPath.Avx512VbmiVl256 when IsAvx512VbmiVlSupported() => EncodeCharsAvx512VbmiVl256(source, destination, alphabetKind),
			Base32SimdPath.Avx512VbmiVl128 when IsAvx512VbmiVlSupported() => EncodeCharsAvx512VbmiVl128(source, destination, alphabetKind),
			Base32SimdPath.Avx512Bw when Avx512BW.IsSupported => EncodeCharsAvx512Bw(source, destination, alphabetKind),
			Base32SimdPath.Avx2 when Avx2.IsSupported => EncodeCharsAvx2(source, destination, alphabetKind),
			Base32SimdPath.Ssse3 when Ssse3.IsSupported => EncodeCharsSsse3(source, destination, alphabetKind),
			_ => 0,
		};
	}

	internal int EncodeCharsBlocksPath(ReadOnlySpan<byte> source, Span<char> destination, Base32SimdPath path)
	{
		return EncodeCharsForced(source, destination, _alphabetKind, path);
	}

	// Keep the complete dispatcher here even though x86 calls the specialized
	// overload below. Its IL size preserves the ARM64 tail call without NoInlining.
	private static int EncodeUtf8Auto(ReadOnlySpan<byte> source, Span<byte> destination, int sourceOffset, int destinationOffset, byte alphabetKind)
	{
		if (alphabetKind is CustomAlphabetKind)
		{
			return 0;
		}

		if (AdvSimd.IsSupported)
		{
			int arm64SourceRemaining = Math.Min(source.Length - sourceOffset, (destination.Length - destinationOffset) / OutputSymbolsPerBlock * InputBytesPerBlock);
			return arm64SourceRemaining >= Arm64EncodeSimdThreshold
				? EncodeUtf8AdvSimd(source, destination, sourceOffset, destinationOffset, alphabetKind)
				: 0;
		}

		int sourceRemaining = Math.Min(source.Length, destination.Length / OutputSymbolsPerBlock * InputBytesPerBlock);

		if (IsAvx512VbmiVlSupported())
		{
			if (sourceRemaining >= X86EncodeVector512Threshold && IsAvx512VbmiSupported())
			{
				return EncodeUtf8Avx512Vbmi(source, destination, alphabetKind);
			}

			if (sourceRemaining >= X86EncodeVector256Threshold)
			{
				return EncodeUtf8Avx512VbmiVl256(source, destination, alphabetKind);
			}

			return sourceRemaining >= X86EncodeVbmiVl128Threshold
				? EncodeUtf8Avx512VbmiVl128(source, destination, alphabetKind)
				: 0;
		}

		if (sourceRemaining >= X86EncodeVector512Threshold && IsAvx512VbmiSupported())
		{
			return EncodeUtf8Avx512Vbmi(source, destination, alphabetKind);
		}

		if (sourceRemaining >= X86EncodeAvx512BwThreshold && Avx512BW.IsSupported)
		{
			return EncodeUtf8Avx512Bw(source, destination, alphabetKind);
		}

		if (sourceRemaining >= X86EncodeVector256Threshold && Avx2.IsSupported)
		{
			return EncodeUtf8Avx2(source, destination, alphabetKind);
		}

		if (sourceRemaining >= X86EncodeVector256Threshold && Ssse3.IsSupported)
		{
			return EncodeUtf8Ssse3(source, destination, alphabetKind);
		}

		return 0;
	}

	private static int EncodeUtf8X86Auto(ReadOnlySpan<byte> source, Span<byte> destination, byte alphabetKind)
	{
		int sourceRemaining = Math.Min(source.Length, destination.Length / OutputSymbolsPerBlock * InputBytesPerBlock);

		if (IsAvx512VbmiVlSupported())
		{
			if (sourceRemaining >= X86EncodeVector512Threshold && IsAvx512VbmiSupported())
			{
				return EncodeUtf8Avx512Vbmi(source, destination, alphabetKind);
			}

			if (sourceRemaining >= X86EncodeVector256Threshold)
			{
				return EncodeUtf8Avx512VbmiVl256(source, destination, alphabetKind);
			}

			return sourceRemaining >= X86EncodeVbmiVl128Threshold
				? EncodeUtf8Avx512VbmiVl128Single(source, destination, alphabetKind)
				: 0;
		}

		if (sourceRemaining >= X86EncodeVector512Threshold && IsAvx512VbmiSupported())
		{
			return EncodeUtf8Avx512Vbmi(source, destination, alphabetKind);
		}

		if (sourceRemaining >= X86EncodeAvx512BwThreshold && Avx512BW.IsSupported)
		{
			return EncodeUtf8Avx512Bw(source, destination, alphabetKind);
		}

		if (sourceRemaining >= X86EncodeVector256Threshold && Avx2.IsSupported)
		{
			return EncodeUtf8Avx2(source, destination, alphabetKind);
		}

		if (sourceRemaining >= X86EncodeVector256Threshold && Ssse3.IsSupported)
		{
			return EncodeUtf8Ssse3(source, destination, alphabetKind);
		}

		return 0;
	}

	private int EncodeUtf8CustomAuto(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int sourceRemaining = Math.Min(source.Length, destination.Length / OutputSymbolsPerBlock * InputBytesPerBlock);

		if (sourceRemaining >= X86EncodeVector512Threshold && IsAvx512VbmiSupported())
		{
			return EncodeUtf8Avx512VbmiCustom(source, destination);
		}

		return sourceRemaining >= X86EncodeVector256Threshold && IsAvx512VbmiVlSupported()
			? EncodeUtf8Avx512VbmiVl256Custom(source, destination)
			: 0;
	}

	private static int EncodeUtf8Forced(ReadOnlySpan<byte> source, Span<byte> destination, byte alphabetKind, Base32SimdPath path)
	{
		if (path is Base32SimdPath.Scalar || alphabetKind is CustomAlphabetKind)
		{
			return 0;
		}

		return path switch
		{
			Base32SimdPath.AdvSimd when AdvSimd.IsSupported => EncodeUtf8AdvSimd(source, destination, 0, 0, alphabetKind),
			Base32SimdPath.Avx512Vbmi when IsAvx512VbmiSupported() => EncodeUtf8Avx512Vbmi(source, destination, alphabetKind),
			Base32SimdPath.Avx512VbmiVl256 when IsAvx512VbmiVlSupported() => EncodeUtf8Avx512VbmiVl256(source, destination, alphabetKind),
			Base32SimdPath.Avx512VbmiVl128 when IsAvx512VbmiVlSupported() => EncodeUtf8Avx512VbmiVl128(source, destination, alphabetKind),
			Base32SimdPath.Avx512Bw when Avx512BW.IsSupported => EncodeUtf8Avx512Bw(source, destination, alphabetKind),
			Base32SimdPath.Avx2 when Avx2.IsSupported => EncodeUtf8Avx2(source, destination, alphabetKind),
			Base32SimdPath.Ssse3 when Ssse3.IsSupported => EncodeUtf8Ssse3(source, destination, alphabetKind),
			_ => 0,
		};
	}

	internal int EncodeUtf8BlocksPath(ReadOnlySpan<byte> source, Span<byte> destination, Base32SimdPath path)
	{
		return EncodeUtf8Forced(source, destination, _alphabetKind, path);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void GetDecodeShuffleMap(byte alphabetKind, out Vector128<byte> deltaCheck, out Vector128<byte> deltaRebase, out byte lowerBound)
	{
		if (alphabetKind is Rfc4648HexAlphabetKind)
		{
			deltaCheck = Vector128.Create(-16, -32, -48, 70, -65, 41, 32, 16, 0, -16, -32, -48, -64, -80, -96, -112).AsByte();
			deltaRebase = Vector128.Create(0, 0, 0, -48, -55, -55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0).AsByte();
			lowerBound = (byte)'0';
		}
		else
		{
			deltaCheck = Vector128.Create(-16, -32, -48, 72, -65, 37, 32, 16, 0, -16, -32, -48, -64, -80, -96, -112).AsByte();
			deltaRebase = Vector128.Create(0, 0, 0, -24, -65, -65, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0).AsByte();
			lowerBound = (byte)'2';
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreDecoded(Vector128<byte> packed, ref byte destination)
	{
		Unsafe.WriteUnaligned(ref destination, packed.AsUInt64().GetElement(0));
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref destination, 8), packed.AsUInt16().GetElement(4));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int DecodeCharsBlocks(ReadOnlySpan<char> source, Span<byte> destination, int fullLength, Base32SimdPath path)
	{
		if (path is not Base32SimdPath.Auto)
		{
			return DecodeCharsForced(source, destination, fullLength, _alphabetKind, path);
		}

		return _alphabetKind is not CustomAlphabetKind && fullLength >= X86DecodeVector128Threshold && destination.Length >= 10
				|| _alphabetKind is CustomAlphabetKind && fullLength >= X86DecodeVector512Threshold && destination.Length >= 40
			? DecodeCharsAuto(source, destination, fullLength, _alphabetKind)
			: 0;
	}

	// DecodeCharsBlocks establishes the minimum source and destination sizes for this dispatcher.
	private int DecodeCharsAuto(ReadOnlySpan<char> source, Span<byte> destination, int fullLength, byte alphabetKind)
	{
		int fullRemaining = Math.Min(fullLength, destination.Length / InputBytesPerBlock * OutputSymbolsPerBlock);

		if (alphabetKind is CustomAlphabetKind)
		{
			return IsAvx512VbmiSupported()
				? DecodeCharsAvx512Vbmi(source, destination, fullLength, alphabetKind)
				: DecodeScalar(source, destination, fullLength);
		}

		if (AdvSimd.IsSupported)
		{
			return DecodeCharsAdvSimd(source, destination, fullLength, alphabetKind);
		}

		if (IsAvx512VbmiVlSupported())
		{
			if (fullRemaining >= X86DecodeVector512Threshold && IsAvx512VbmiSupported())
			{
				return DecodeCharsAvx512Vbmi(source, destination, fullLength, alphabetKind);
			}

			if (fullRemaining >= X86DecodeVector256Threshold)
			{
				return DecodeCharsAvx512VbmiVl256(source, destination, fullLength, alphabetKind);
			}

			return DecodeCharsVector128(source, destination, fullLength, alphabetKind);
		}

		if (fullRemaining >= X86DecodeVector512Threshold && IsAvx512VbmiSupported())
		{
			return DecodeCharsAvx512Vbmi(source, destination, fullLength, alphabetKind);
		}

		if (fullRemaining >= X86DecodeVector512Threshold && Avx512BW.IsSupported)
		{
			return DecodeCharsAvx512(source, destination, fullLength, alphabetKind);
		}

		if (fullRemaining >= X86DecodeVector256Threshold && Avx2.IsSupported)
		{
			return DecodeCharsAvx2(source, destination, fullLength, alphabetKind);
		}

		if (Ssse3.IsSupported)
		{
			return DecodeCharsVector128(source, destination, fullLength, alphabetKind);
		}

		return fullRemaining >= X86DecodeVector512Threshold
			? DecodeScalar(source, destination, fullLength)
			: 0;
	}

	private int DecodeCharsForced(ReadOnlySpan<char> source, Span<byte> destination, int fullLength, byte alphabetKind, Base32SimdPath path)
	{
		if (path is Base32SimdPath.Scalar || alphabetKind is CustomAlphabetKind)
		{
			return DecodeScalar(source, destination, fullLength);
		}

		return path switch
		{
			Base32SimdPath.AdvSimd when AdvSimd.IsSupported => DecodeCharsAdvSimd(source, destination, fullLength, alphabetKind),
			Base32SimdPath.Avx512Vbmi when IsAvx512VbmiSupported() => DecodeCharsAvx512Vbmi(source, destination, fullLength, alphabetKind),
			Base32SimdPath.Avx512VbmiVl256 when IsAvx512VbmiVlSupported() => DecodeCharsAvx512VbmiVl256(source, destination, fullLength, alphabetKind),
			Base32SimdPath.Avx512VbmiVl128 when IsAvx512VbmiVlSupported() => DecodeCharsVector128(source, destination, fullLength, alphabetKind),
			Base32SimdPath.Avx512Bw when Avx512BW.IsSupported => DecodeCharsAvx512(source, destination, fullLength, alphabetKind),
			Base32SimdPath.Avx2 when Avx2.IsSupported => DecodeCharsAvx2(source, destination, fullLength, alphabetKind),
			Base32SimdPath.Ssse3 when Ssse3.IsSupported => DecodeCharsVector128(source, destination, fullLength, alphabetKind),
			_ => 0,
		};
	}

	internal int DecodeCharsBlocksPath(ReadOnlySpan<char> source, Span<byte> destination, Base32SimdPath path)
	{
		return DecodeCharsForced(source, destination, source.Length & ~7, _alphabetKind, path);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int DecodeUtf8Blocks(ReadOnlySpan<byte> source, Span<byte> destination, int fullLength, Base32SimdPath path)
	{
		return path is Base32SimdPath.Auto
			? DecodeUtf8Auto(source, destination, fullLength, _alphabetKind)
			: DecodeUtf8Forced(source, destination, fullLength, _alphabetKind, path);
	}

	private int DecodeUtf8Auto(ReadOnlySpan<byte> source, Span<byte> destination, int fullLength, byte alphabetKind)
	{
		int fullRemaining = Math.Min(fullLength, destination.Length / InputBytesPerBlock * OutputSymbolsPerBlock);

		if (alphabetKind is CustomAlphabetKind)
		{
			return fullRemaining >= X86DecodeVector512Threshold && IsAvx512VbmiSupported()
				? DecodeUtf8Avx512Vbmi(source, destination, fullLength, alphabetKind)
				: DecodeScalar(source, destination, fullLength);
		}

		if (AdvSimd.IsSupported)
		{
			return fullRemaining >= Arm64DecodeSimdThreshold
				? DecodeUtf8AdvSimd(source, destination, fullLength, alphabetKind)
				: DecodeScalar(source, destination, fullLength);
		}

		if (IsAvx512VbmiVlSupported())
		{
			if (fullRemaining >= X86DecodeVector512Threshold && IsAvx512VbmiSupported())
			{
				return DecodeUtf8Avx512Vbmi(source, destination, fullLength, alphabetKind);
			}

			if (fullRemaining >= X86DecodeVector256Threshold)
			{
				return DecodeUtf8Avx512VbmiVl256(source, destination, fullLength, alphabetKind);
			}

			return fullRemaining >= X86DecodeVector128Threshold
				? DecodeUtf8Vector128(source, destination, fullLength, alphabetKind)
				: DecodeScalar(source, destination, fullLength);
		}

		if (fullRemaining >= X86DecodeVector512Threshold && IsAvx512VbmiSupported())
		{
			return DecodeUtf8Avx512Vbmi(source, destination, fullLength, alphabetKind);
		}

		if (fullRemaining >= X86DecodeVector512Threshold && Avx512BW.IsSupported)
		{
			return DecodeUtf8Avx512(source, destination, fullLength, alphabetKind);
		}

		if (fullRemaining >= X86DecodeVector256Threshold && Avx2.IsSupported)
		{
			return DecodeUtf8Avx2(source, destination, fullLength, alphabetKind);
		}

		if (fullRemaining >= X86DecodeVector128Threshold && Ssse3.IsSupported)
		{
			return DecodeUtf8Vector128(source, destination, fullLength, alphabetKind);
		}

		return DecodeScalar(source, destination, fullLength);
	}

	private int DecodeUtf8Forced(ReadOnlySpan<byte> source, Span<byte> destination, int fullLength, byte alphabetKind, Base32SimdPath path)
	{
		if (path is Base32SimdPath.Scalar || alphabetKind is CustomAlphabetKind)
		{
			return DecodeScalar(source, destination, fullLength);
		}

		return path switch
		{
			Base32SimdPath.AdvSimd when AdvSimd.IsSupported => DecodeUtf8AdvSimd(source, destination, fullLength, alphabetKind),
			Base32SimdPath.Avx512Vbmi when IsAvx512VbmiSupported() => DecodeUtf8Avx512Vbmi(source, destination, fullLength, alphabetKind),
			Base32SimdPath.Avx512VbmiVl256 when IsAvx512VbmiVlSupported() => DecodeUtf8Avx512VbmiVl256(source, destination, fullLength, alphabetKind),
			Base32SimdPath.Avx512VbmiVl128 when IsAvx512VbmiVlSupported() => DecodeUtf8Vector128(source, destination, fullLength, alphabetKind),
			Base32SimdPath.Avx512Bw when Avx512BW.IsSupported => DecodeUtf8Avx512(source, destination, fullLength, alphabetKind),
			Base32SimdPath.Avx2 when Avx2.IsSupported => DecodeUtf8Avx2(source, destination, fullLength, alphabetKind),
			Base32SimdPath.Ssse3 when Ssse3.IsSupported => DecodeUtf8Vector128(source, destination, fullLength, alphabetKind),
			_ => 0,
		};
	}

	internal int DecodeUtf8BlocksPath(ReadOnlySpan<byte> source, Span<byte> destination, Base32SimdPath path)
	{
		return DecodeUtf8Forced(source, destination, source.Length & ~7, _alphabetKind, path);
	}
}
