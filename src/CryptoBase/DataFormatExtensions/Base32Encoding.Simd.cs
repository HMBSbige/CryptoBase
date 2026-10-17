namespace CryptoBase.DataFormatExtensions;

public sealed partial class Base32Encoding
{
	private const byte CustomAlphabetKind = 0;
	private const byte Rfc4648AlphabetKind = 1;
	private const byte Rfc4648HexAlphabetKind = 2;
	private const int Arm64EncodeSimdThreshold = 20;
	private const int Arm64DecodeSimdThreshold = 16;
	private const int X86EncodeVbmiVl128Threshold = 10;
	private const int EncodeShortSimdThreshold = 10;
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
	private static void StoreSymbols<T>(Vector128<byte> value, ref T destination) where T : unmanaged
	{
		if (typeof(T) != typeof(char))
		{
			value.StoreUnsafe(ref Unsafe.As<T, byte>(ref destination));
			return;
		}

		ref ushort destinationReference = ref Unsafe.As<T, ushort>(ref destination);
		Vector128.WidenLower(value).StoreUnsafe(ref destinationReference);
		Vector128.WidenUpper(value).StoreUnsafe(ref destinationReference, 8);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreSymbols<T>(Vector512<byte> value, ref T destination) where T : unmanaged
	{
		if (typeof(T) != typeof(char))
		{
			value.StoreUnsafe(ref Unsafe.As<T, byte>(ref destination));
			return;
		}

		ref ushort destinationReference = ref Unsafe.As<T, ushort>(ref destination);
		Vector512.WidenLower(value).StoreUnsafe(ref destinationReference);
		Vector512.WidenUpper(value).StoreUnsafe(ref destinationReference, 32);
	}

	// Char input is narrowed with saturation, which turns every char above U+00FF into a byte the decoders reject, so no separate ASCII
	// check is needed. These loads only feed fixed alphabets, so x86 uses the cheaper signed pack: U+0100..U+7FFF -> 0xFF, U+8000..U+FFFF -> 0x00.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> LoadSymbols128<T>(ref T source) where T : unmanaged
	{
		if (typeof(T) != typeof(char))
		{
			return Vector128.LoadUnsafe(ref Unsafe.As<T, byte>(ref source));
		}

		ref ushort sourceReference = ref Unsafe.As<T, ushort>(ref source);
		Vector128<ushort> lower = Vector128.LoadUnsafe(ref sourceReference);
		Vector128<ushort> upper = Vector128.LoadUnsafe(ref sourceReference, 8);

		if (Sse2.IsSupported)
		{
			return Sse2.PackUnsignedSaturate(lower.AsInt16(), upper.AsInt16());
		}

		return Vector128.NarrowWithSaturation(lower, upper);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> LoadSymbols256<T>(ref T source) where T : unmanaged
	{
		if (typeof(T) != typeof(char))
		{
			return Vector256.LoadUnsafe(ref Unsafe.As<T, byte>(ref source));
		}

		ref short sourceReference = ref Unsafe.As<T, short>(ref source);
		Vector256<byte> packed = Avx2.PackUnsignedSaturate(Vector256.LoadUnsafe(ref sourceReference), Vector256.LoadUnsafe(ref sourceReference, 16));
		return Avx2.Permute4x64(packed.AsUInt64(), 0b11_01_10_00).AsByte();
	}

	// Custom alphabets may contain NUL, so the 512-bit loads keep unsigned saturation and every char above U+00FF becomes 0xFF.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector512<byte> LoadSymbols512<T>(ref T source) where T : unmanaged
	{
		if (typeof(T) != typeof(char))
		{
			return Vector512.LoadUnsafe(ref Unsafe.As<T, byte>(ref source));
		}

		ref ushort sourceReference = ref Unsafe.As<T, ushort>(ref source);
		return Vector512.NarrowWithSaturation(Vector512.LoadUnsafe(ref sourceReference), Vector512.LoadUnsafe(ref sourceReference, 32));
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
	private static bool UseAvx512Vbmi()
	{
		return Vector512.IsHardwareAccelerated && IsAvx512VbmiSupported();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static bool UseAvx512Bw()
	{
		return Vector512.IsHardwareAccelerated && Avx512BW.IsSupported;
	}

	// SIMD encoders cover every whole block: after the full vectors, one more vector ends at the last whole block and rewrites the symbols
	// it overlaps with identical values. That vector spans minimumBlocks blocks, so fewer blocks are left to the scalar loop.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int GetEncodeBlockCount(int sourceLength, int destinationLength, int minimumBlocks)
	{
		int blockCount = Math.Min(sourceLength / InputBytesPerBlock, destinationLength / OutputSymbolsPerBlock);
		return blockCount < minimumBlocks ? 0 : blockCount;
	}

	// Two or three whole blocks below the vector loop thresholds; a third block is covered by a second vector one block later.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int GetEncodeShortBlockCount(int sourceLength, int destinationLength)
	{
		return Math.Min(GetEncodeBlockCount(sourceLength, destinationLength, 2), 3);
	}

	// Ten bytes as two overlapping qwords so short inputs never read past their second block; bytes 8 and 9 land in lanes 14 and 15.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> LoadTenBytes(ref byte source)
	{
		return Vector128.Create(Unsafe.ReadUnaligned<ulong>(ref source), Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref source, 2))).AsByte();
	}

	// Keep the offsets in the AdvSimd call chain. On .NET 10 ARM64, forwarding the
	// caller's zero-valued registers is faster than materializing two zero arguments.
	private static int EncodeCharsAdvSimdAuto(ReadOnlySpan<byte> source, Span<char> destination, int sourceOffset, int destinationOffset, byte[] alphabet)
	{
		int sourceRemaining = Math.Min(source.Length - sourceOffset, (destination.Length - destinationOffset) / OutputSymbolsPerBlock * InputBytesPerBlock);

		if (sourceRemaining >= Arm64EncodeSimdThreshold)
		{
			return EncodeAdvSimd(source, destination, sourceOffset, destinationOffset, alphabet);
		}

		return sourceRemaining >= EncodeShortSimdThreshold
			? EncodeAdvSimdShort(source, destination, sourceOffset, destinationOffset, alphabet)
			: 0;
	}

	private static int EncodeCharsAuto(ReadOnlySpan<byte> source, Span<char> destination, byte alphabetKind)
	{
		int sourceRemaining = Math.Min(source.Length, destination.Length / OutputSymbolsPerBlock * InputBytesPerBlock);

		if (IsAvx512VbmiVlSupported())
		{
			if (sourceRemaining >= X86EncodeVector512Threshold && UseAvx512Vbmi())
			{
				return EncodeCharsAvx512Vbmi(source, destination, alphabetKind);
			}

			if (sourceRemaining >= X86EncodeVector256Threshold)
			{
				return EncodeCharsAvx512VbmiVl256(source, destination, alphabetKind);
			}

			return sourceRemaining >= X86EncodeVbmiVl128Threshold
				? EncodeAvx512VbmiVl128Short(source, destination, GetShortAlphabet(alphabetKind))
				: 0;
		}

		if (sourceRemaining >= X86EncodeVector512Threshold && UseAvx512Vbmi())
		{
			return EncodeCharsAvx512Vbmi(source, destination, alphabetKind);
		}

		if (sourceRemaining >= X86EncodeAvx512BwThreshold && UseAvx512Bw())
		{
			return EncodeAvx512Bw(source, destination, alphabetKind);
		}

		if (sourceRemaining >= X86EncodeVector256Threshold && Avx2.IsSupported)
		{
			return EncodeAvx2(source, destination, alphabetKind);
		}

		if (!Ssse3.IsSupported)
		{
			return 0;
		}

		if (sourceRemaining >= X86EncodeVector256Threshold)
		{
			return EncodeSsse3(source, destination, alphabetKind);
		}

		return sourceRemaining >= EncodeShortSimdThreshold
			? EncodeSsse3Short(source, destination, alphabetKind)
			: 0;
	}

	private int EncodeCharsCustomAuto(ReadOnlySpan<byte> source, Span<char> destination)
	{
		int sourceRemaining = Math.Min(source.Length, destination.Length / OutputSymbolsPerBlock * InputBytesPerBlock);

		if (sourceRemaining >= X86EncodeVector512Threshold && UseAvx512Vbmi())
		{
			return EncodeCharsAvx512VbmiCustom(source, destination);
		}

		if (sourceRemaining < X86EncodeVector256Threshold)
		{
			return 0;
		}

		if (IsAvx512VbmiVlSupported())
		{
			return EncodeCharsAvx512VbmiVl256Custom(source, destination);
		}

		return Avx2.IsSupported ? EncodeAvx2Custom(source, destination) : 0;
	}

	private static int EncodeCharsForced(ReadOnlySpan<byte> source, Span<char> destination, byte[] alphabet, byte alphabetKind, Base32SimdPath path)
	{
		if (path is Base32SimdPath.Scalar || alphabetKind is CustomAlphabetKind)
		{
			return 0;
		}

		return path switch
		{
			Base32SimdPath.AdvSimd when AdvSimd.IsSupported => EncodeAdvSimd(source, destination, 0, 0, alphabet),
			Base32SimdPath.Avx512Vbmi when IsAvx512VbmiSupported() => EncodeCharsAvx512Vbmi(source, destination, alphabetKind),
			Base32SimdPath.Avx512VbmiVl256 when IsAvx512VbmiVlSupported() => EncodeCharsAvx512VbmiVl256(source, destination, alphabetKind),
			Base32SimdPath.Avx512VbmiVl128 when IsAvx512VbmiVlSupported() => EncodeAvx512VbmiVl128(source, destination, alphabetKind),
			Base32SimdPath.Avx512Bw when Avx512BW.IsSupported => EncodeAvx512Bw(source, destination, alphabetKind),
			Base32SimdPath.Avx2 when Avx2.IsSupported => EncodeAvx2(source, destination, alphabetKind),
			Base32SimdPath.Ssse3 when Ssse3.IsSupported => EncodeSsse3(source, destination, alphabetKind),
			_ => 0,
		};
	}

	internal int EncodeCharsBlocksPath(ReadOnlySpan<byte> source, Span<char> destination, Base32SimdPath path)
	{
		return EncodeCharsForced(source, destination, _alphabet, _alphabetKind, path);
	}

	// Keep the complete dispatcher here even though x86 calls the specialized
	// overload below. Its IL size preserves the ARM64 tail call without NoInlining.
	private static int EncodeUtf8Auto(ReadOnlySpan<byte> source, Span<byte> destination, int sourceOffset, int destinationOffset, byte[] alphabet, byte alphabetKind)
	{
		if (AdvSimd.IsSupported)
		{
			int arm64SourceRemaining = Math.Min(source.Length - sourceOffset, (destination.Length - destinationOffset) / OutputSymbolsPerBlock * InputBytesPerBlock);

			if (arm64SourceRemaining >= Arm64EncodeSimdThreshold)
			{
				return EncodeAdvSimd(source, destination, sourceOffset, destinationOffset, alphabet);
			}

			return arm64SourceRemaining >= EncodeShortSimdThreshold
				? EncodeAdvSimdShort(source, destination, sourceOffset, destinationOffset, alphabet)
				: 0;
		}

		if (alphabetKind is CustomAlphabetKind)
		{
			return 0;
		}

		int sourceRemaining = Math.Min(source.Length, destination.Length / OutputSymbolsPerBlock * InputBytesPerBlock);

		if (IsAvx512VbmiVlSupported())
		{
			if (sourceRemaining >= X86EncodeVector512Threshold && UseAvx512Vbmi())
			{
				return EncodeUtf8Avx512Vbmi(source, destination, alphabetKind);
			}

			if (sourceRemaining >= X86EncodeVector256Threshold)
			{
				return EncodeUtf8Avx512VbmiVl256(source, destination, alphabetKind);
			}

			return sourceRemaining >= X86EncodeVbmiVl128Threshold
				? EncodeAvx512VbmiVl128(source, destination, alphabetKind)
				: 0;
		}

		if (sourceRemaining >= X86EncodeVector512Threshold && UseAvx512Vbmi())
		{
			return EncodeUtf8Avx512Vbmi(source, destination, alphabetKind);
		}

		if (sourceRemaining >= X86EncodeAvx512BwThreshold && UseAvx512Bw())
		{
			return EncodeAvx512Bw(source, destination, alphabetKind);
		}

		if (sourceRemaining >= X86EncodeVector256Threshold && Avx2.IsSupported)
		{
			return EncodeAvx2(source, destination, alphabetKind);
		}

		if (!Ssse3.IsSupported)
		{
			return 0;
		}

		if (sourceRemaining >= X86EncodeVector256Threshold)
		{
			return EncodeSsse3(source, destination, alphabetKind);
		}

		return sourceRemaining >= EncodeShortSimdThreshold
			? EncodeSsse3Short(source, destination, alphabetKind)
			: 0;
	}

	private static int EncodeUtf8X86Auto(ReadOnlySpan<byte> source, Span<byte> destination, byte alphabetKind)
	{
		int sourceRemaining = Math.Min(source.Length, destination.Length / OutputSymbolsPerBlock * InputBytesPerBlock);

		if (IsAvx512VbmiVlSupported())
		{
			if (sourceRemaining >= X86EncodeVector512Threshold && UseAvx512Vbmi())
			{
				return EncodeUtf8Avx512Vbmi(source, destination, alphabetKind);
			}

			if (sourceRemaining >= X86EncodeVector256Threshold)
			{
				return EncodeUtf8Avx512VbmiVl256(source, destination, alphabetKind);
			}

			return sourceRemaining >= X86EncodeVbmiVl128Threshold
				? EncodeAvx512VbmiVl128Short(source, destination, GetShortAlphabet(alphabetKind))
				: 0;
		}

		if (sourceRemaining >= X86EncodeVector512Threshold && UseAvx512Vbmi())
		{
			return EncodeUtf8Avx512Vbmi(source, destination, alphabetKind);
		}

		if (sourceRemaining >= X86EncodeAvx512BwThreshold && UseAvx512Bw())
		{
			return EncodeAvx512Bw(source, destination, alphabetKind);
		}

		if (sourceRemaining >= X86EncodeVector256Threshold && Avx2.IsSupported)
		{
			return EncodeAvx2(source, destination, alphabetKind);
		}

		if (!Ssse3.IsSupported)
		{
			return 0;
		}

		if (sourceRemaining >= X86EncodeVector256Threshold)
		{
			return EncodeSsse3(source, destination, alphabetKind);
		}

		return sourceRemaining >= EncodeShortSimdThreshold
			? EncodeSsse3Short(source, destination, alphabetKind)
			: 0;
	}

	private int EncodeUtf8CustomAuto(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int sourceRemaining = Math.Min(source.Length, destination.Length / OutputSymbolsPerBlock * InputBytesPerBlock);

		if (sourceRemaining >= X86EncodeVector512Threshold && UseAvx512Vbmi())
		{
			return EncodeUtf8Avx512VbmiCustom(source, destination);
		}

		if (sourceRemaining < X86EncodeVector256Threshold)
		{
			return 0;
		}

		if (IsAvx512VbmiVlSupported())
		{
			return EncodeUtf8Avx512VbmiVl256Custom(source, destination);
		}

		return Avx2.IsSupported ? EncodeAvx2Custom(source, destination) : 0;
	}

	private static int EncodeUtf8Forced(ReadOnlySpan<byte> source, Span<byte> destination, byte[] alphabet, byte alphabetKind, Base32SimdPath path)
	{
		if (path is Base32SimdPath.Scalar || alphabetKind is CustomAlphabetKind)
		{
			return 0;
		}

		return path switch
		{
			Base32SimdPath.AdvSimd when AdvSimd.IsSupported => EncodeAdvSimd(source, destination, 0, 0, alphabet),
			Base32SimdPath.Avx512Vbmi when IsAvx512VbmiSupported() => EncodeUtf8Avx512Vbmi(source, destination, alphabetKind),
			Base32SimdPath.Avx512VbmiVl256 when IsAvx512VbmiVlSupported() => EncodeUtf8Avx512VbmiVl256(source, destination, alphabetKind),
			Base32SimdPath.Avx512VbmiVl128 when IsAvx512VbmiVlSupported() => EncodeAvx512VbmiVl128(source, destination, alphabetKind),
			Base32SimdPath.Avx512Bw when Avx512BW.IsSupported => EncodeAvx512Bw(source, destination, alphabetKind),
			Base32SimdPath.Avx2 when Avx2.IsSupported => EncodeAvx2(source, destination, alphabetKind),
			Base32SimdPath.Ssse3 when Ssse3.IsSupported => EncodeSsse3(source, destination, alphabetKind),
			_ => 0,
		};
	}

	internal int EncodeUtf8BlocksPath(ReadOnlySpan<byte> source, Span<byte> destination, Base32SimdPath path)
	{
		return EncodeUtf8Forced(source, destination, _alphabet, _alphabetKind, path);
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
			return DecodeForced(source, destination, fullLength, _alphabetKind, path);
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
			// No narrower custom-alphabet decoder exists, so this ignores Vector512.IsHardwareAccelerated.
			return IsAvx512VbmiSupported()
				? DecodeAvx512Vbmi(source, destination, fullLength, alphabetKind)
				: DecodeScalar(source, destination, fullLength);
		}

		if (AdvSimd.IsSupported)
		{
			return DecodeAdvSimd(source, destination, fullLength, alphabetKind);
		}

		if (IsAvx512VbmiVlSupported())
		{
			if (fullRemaining >= X86DecodeVector512Threshold && UseAvx512Vbmi())
			{
				return DecodeAvx512Vbmi(source, destination, fullLength, alphabetKind);
			}

			if (fullRemaining >= X86DecodeVector256Threshold)
			{
				return DecodeAvx512VbmiVl256(source, destination, fullLength, alphabetKind);
			}

			return DecodeVector128(source, destination, fullLength, alphabetKind);
		}

		if (fullRemaining >= X86DecodeVector512Threshold && UseAvx512Vbmi())
		{
			return DecodeAvx512Vbmi(source, destination, fullLength, alphabetKind);
		}

		if (fullRemaining >= X86DecodeVector512Threshold && UseAvx512Bw())
		{
			return DecodeAvx512(source, destination, fullLength, alphabetKind);
		}

		if (fullRemaining >= X86DecodeVector256Threshold && Avx2.IsSupported)
		{
			return DecodeAvx2(source, destination, fullLength, alphabetKind);
		}

		if (Ssse3.IsSupported)
		{
			return DecodeVector128(source, destination, fullLength, alphabetKind);
		}

		return fullRemaining >= X86DecodeVector512Threshold
			? DecodeScalar(source, destination, fullLength)
			: 0;
	}

	private int DecodeForced<T>(ReadOnlySpan<T> source, Span<byte> destination, int fullLength, byte alphabetKind, Base32SimdPath path) where T : unmanaged
	{
		if (path is Base32SimdPath.Scalar || alphabetKind is CustomAlphabetKind)
		{
			return DecodeScalar(source, destination, fullLength);
		}

		return path switch
		{
			Base32SimdPath.AdvSimd when AdvSimd.IsSupported => DecodeAdvSimd(source, destination, fullLength, alphabetKind),
			Base32SimdPath.Avx512Vbmi when IsAvx512VbmiSupported() => DecodeAvx512Vbmi(source, destination, fullLength, alphabetKind),
			Base32SimdPath.Avx512VbmiVl256 when IsAvx512VbmiVlSupported() => DecodeAvx512VbmiVl256(source, destination, fullLength, alphabetKind),
			Base32SimdPath.Avx512VbmiVl128 when IsAvx512VbmiVlSupported() => DecodeVector128(source, destination, fullLength, alphabetKind),
			Base32SimdPath.Avx512Bw when Avx512BW.IsSupported => DecodeAvx512(source, destination, fullLength, alphabetKind),
			Base32SimdPath.Avx2 when Avx2.IsSupported => DecodeAvx2(source, destination, fullLength, alphabetKind),
			Base32SimdPath.Ssse3 when Ssse3.IsSupported => DecodeVector128(source, destination, fullLength, alphabetKind),
			_ => 0,
		};
	}

	internal int DecodeCharsBlocksPath(ReadOnlySpan<char> source, Span<byte> destination, Base32SimdPath path)
	{
		return DecodeForced(source, destination, source.Length & ~7, _alphabetKind, path);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int DecodeUtf8Blocks(ReadOnlySpan<byte> source, Span<byte> destination, int fullLength, Base32SimdPath path)
	{
		return path is Base32SimdPath.Auto
			? DecodeUtf8Auto(source, destination, fullLength, _alphabetKind)
			: DecodeForced(source, destination, fullLength, _alphabetKind, path);
	}

	private int DecodeUtf8Auto(ReadOnlySpan<byte> source, Span<byte> destination, int fullLength, byte alphabetKind)
	{
		int fullRemaining = Math.Min(fullLength, destination.Length / InputBytesPerBlock * OutputSymbolsPerBlock);

		if (alphabetKind is CustomAlphabetKind)
		{
			return fullRemaining >= X86DecodeVector512Threshold && IsAvx512VbmiSupported()
				? DecodeAvx512Vbmi(source, destination, fullLength, alphabetKind)
				: DecodeScalar(source, destination, fullLength);
		}

		if (AdvSimd.IsSupported)
		{
			return fullRemaining >= Arm64DecodeSimdThreshold
				? DecodeAdvSimd(source, destination, fullLength, alphabetKind)
				: DecodeScalar(source, destination, fullLength);
		}

		if (IsAvx512VbmiVlSupported())
		{
			if (fullRemaining >= X86DecodeVector512Threshold && UseAvx512Vbmi())
			{
				return DecodeAvx512Vbmi(source, destination, fullLength, alphabetKind);
			}

			if (fullRemaining >= X86DecodeVector256Threshold)
			{
				return DecodeAvx512VbmiVl256(source, destination, fullLength, alphabetKind);
			}

			return fullRemaining >= X86DecodeVector128Threshold
				? DecodeVector128(source, destination, fullLength, alphabetKind)
				: DecodeScalar(source, destination, fullLength);
		}

		if (fullRemaining >= X86DecodeVector512Threshold && UseAvx512Vbmi())
		{
			return DecodeAvx512Vbmi(source, destination, fullLength, alphabetKind);
		}

		if (fullRemaining >= X86DecodeVector512Threshold && UseAvx512Bw())
		{
			return DecodeAvx512(source, destination, fullLength, alphabetKind);
		}

		if (fullRemaining >= X86DecodeVector256Threshold && Avx2.IsSupported)
		{
			return DecodeAvx2(source, destination, fullLength, alphabetKind);
		}

		if (fullRemaining >= X86DecodeVector128Threshold && Ssse3.IsSupported)
		{
			return DecodeVector128(source, destination, fullLength, alphabetKind);
		}

		return DecodeScalar(source, destination, fullLength);
	}

	internal int DecodeUtf8BlocksPath(ReadOnlySpan<byte> source, Span<byte> destination, Base32SimdPath path)
	{
		return DecodeForced(source, destination, source.Length & ~7, _alphabetKind, path);
	}
}
