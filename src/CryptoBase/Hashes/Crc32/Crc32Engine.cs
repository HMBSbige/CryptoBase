using CryptoBase.Hashes.Crc32C;
using System.Numerics;
using AesArm = System.Runtime.Intrinsics.Arm.Aes;
using Crc32Arm = System.Runtime.Intrinsics.Arm.Crc32;

namespace CryptoBase.Hashes.Crc32;

internal static class Crc32Engine
{
	internal const uint InitialState = uint.MaxValue;

	private const int VectorThresholdWithoutCrcInstruction = 16;
	private const int VectorThresholdWithCrcInstruction = 128;

	private const int X86Avx512Threshold = 256;

	// One 128-byte batch is marginally faster through the four-stream XMM path.
	private const int IeeeX86Avx2Threshold = 129;
	private const int CastagnoliX86Avx2Threshold = 512;
	private const int IeeeX86Vector128Threshold = 16;
	private const int CastagnoliX86Vector128Threshold = 1024;
	private const int Arm64HybridThresholdInBytes = 6 * 1024;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static uint Update<TAlgorithm>(uint state, ReadOnlySpan<byte> source) where TAlgorithm : unmanaged
	{
		bool isIeee = IsIeee<TAlgorithm>();

		if (!isIeee && Sse42.IsSupported && source.Length < GetCastagnoliX86VectorThreshold())
		{
			return UpdateHardware<TAlgorithm>(state, source);
		}

		if
		(
			isIeee
			&& source.Length >= Arm64HybridThresholdInBytes
			&& Crc32Arm.Arm64.IsSupported
			&& AesArm.IsSupported
			&& AdvSimd.IsSupported
		)
		{
			state = Crc32Vectorized.UpdateHybridArm64(state, source, out int bytesConsumed);

			if (bytesConsumed == source.Length)
			{
				return state;
			}

			source = source.Slice(bytesConsumed);
		}

		if (Pclmulqdq.IsSupported)
		{
			if (source.Length >= X86Avx512Threshold && Avx512BW.IsSupported && Pclmulqdq.V512.IsSupported)
			{
				return UpdateX86512<TAlgorithm>(state, source);
			}

			int avx2Threshold = isIeee ? IeeeX86Avx2Threshold : CastagnoliX86Avx2Threshold;

			if (source.Length >= avx2Threshold && Avx2.IsSupported && Pclmulqdq.V256.IsSupported)
			{
				return UpdateX86256<TAlgorithm>(state, source);
			}

			int vector128Threshold = isIeee
				? IeeeX86Vector128Threshold
				: Sse42.X64.IsSupported
					? CastagnoliX86Vector128Threshold
					: Sse42.IsSupported
						? VectorThresholdWithCrcInstruction
						: VectorThresholdWithoutCrcInstruction;

			if (source.Length >= vector128Threshold)
			{
				return UpdateX86128<TAlgorithm>(state, source);
			}
		}

		int armVectorThreshold = Crc32Arm.IsSupported ? VectorThresholdWithCrcInstruction : VectorThresholdWithoutCrcInstruction;

		if
		(
			BitConverter.IsLittleEndian
			&& source.Length >= armVectorThreshold
			&& AesArm.IsSupported
			&& AdvSimd.IsSupported
		)
		{
			state = Crc32Vectorized.UpdateArm<TAlgorithm>(state, source);
			int bytesConsumed = source.Length - source.Length % Vector128<byte>.Count;

			if (bytesConsumed == source.Length)
			{
				return state;
			}

			source = source.Slice(bytesConsumed);
		}

		return UpdateScalar<TAlgorithm>(state, source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int GetCastagnoliX86VectorThreshold()
	{
		if (!Pclmulqdq.IsSupported)
		{
			return int.MaxValue;
		}

		if (Avx512BW.IsSupported && Pclmulqdq.V512.IsSupported)
		{
			return X86Avx512Threshold;
		}

		if (Avx2.IsSupported && Pclmulqdq.V256.IsSupported)
		{
			return CastagnoliX86Avx2Threshold;
		}

		return Sse42.X64.IsSupported ? CastagnoliX86Vector128Threshold : VectorThresholdWithCrcInstruction;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void Finalize(uint state, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, sizeof(uint), nameof(destination));
		BinaryPrimitives.WriteUInt32BigEndian(destination, ~state);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static uint UpdateScalar<TAlgorithm>(uint state, ReadOnlySpan<byte> source) where TAlgorithm : unmanaged
	{
		bool isIeee = IsIeee<TAlgorithm>();

		if (Crc32Arm.IsSupported || !isIeee && Sse42.IsSupported)
		{
			return UpdateHardware<TAlgorithm>(state, source);
		}

		return Crc32Software.Update<TAlgorithm>(state, source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool IsIeee<TAlgorithm>() where TAlgorithm : unmanaged
	{
		bool isIeee = typeof(TAlgorithm) == typeof(Crc32HashAlgorithm);
		Debug.Assert(isIeee || typeof(TAlgorithm) == typeof(Crc32CHashAlgorithm));
		return isIeee;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint UpdateX86512<TAlgorithm>(uint state, ReadOnlySpan<byte> source) where TAlgorithm : unmanaged
	{
		ref readonly Crc32X86FoldingConstants constants = ref GetX86Constants<TAlgorithm>();
		Vector128<ulong> folded = Crc32Vectorized.FoldX86512(state, source, in constants, out int bytesConsumed);
		return FinishX86<TAlgorithm>(folded, source, bytesConsumed);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint UpdateX86256<TAlgorithm>(uint state, ReadOnlySpan<byte> source) where TAlgorithm : unmanaged
	{
		ref readonly Crc32X86FoldingConstants constants = ref GetX86Constants<TAlgorithm>();
		Vector128<ulong> folded = Crc32Vectorized.FoldX86256(state, source, in constants, out int bytesConsumed);
		return FinishX86<TAlgorithm>(folded, source, bytesConsumed);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint UpdateX86128<TAlgorithm>(uint state, ReadOnlySpan<byte> source) where TAlgorithm : unmanaged
	{
		ref readonly Crc32X86FoldingConstants constants = ref GetX86Constants<TAlgorithm>();
		Vector128<ulong> folded = Crc32Vectorized.FoldX86128(state, source, in constants, out int bytesConsumed);
		return FinishX86<TAlgorithm>(folded, source, bytesConsumed);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint FinishX86<TAlgorithm>(Vector128<ulong> folded, ReadOnlySpan<byte> source, int bytesConsumed) where TAlgorithm : unmanaged
	{
		uint state;

		if (IsIeee<TAlgorithm>())
		{
			state = Crc32Vectorized.ReduceIeeeX86(folded);
		}
		else
		{
			state = Sse42.X64.IsSupported
				? Crc32Vectorized.ReduceCastagnoliX86(folded)
				: Crc32Vectorized.ReduceCastagnoliBarrettX86(folded);
		}

		return bytesConsumed < source.Length
			? UpdateX86Tail<TAlgorithm>(state, source.Slice(bytesConsumed))
			: state;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static uint UpdateX86Tail<TAlgorithm>(uint state, ReadOnlySpan<byte> source) where TAlgorithm : unmanaged
	{
		return UpdateScalar<TAlgorithm>(state, source);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static ref readonly Crc32X86FoldingConstants GetX86Constants<TAlgorithm>() where TAlgorithm : unmanaged
	{
		if (IsIeee<TAlgorithm>())
		{
			return ref Crc32Vectorized.IeeeX86Constants;
		}

		return ref Crc32Vectorized.CastagnoliX86Constants;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint UpdateHardware<TAlgorithm>(uint state, ReadOnlySpan<byte> source) where TAlgorithm : unmanaged
	{
		bool isIeee = IsIeee<TAlgorithm>();
		Debug.Assert(Crc32Arm.IsSupported || !isIeee && Sse42.IsSupported);
		ref byte sourceRef = ref source.GetReference();
		int length = source.Length;

		if (Sse42.X64.IsSupported || Crc32Arm.Arm64.IsSupported)
		{
			while (length >= sizeof(ulong))
			{
				ulong value = Unsafe.ReadUnaligned<ulong>(ref sourceRef);
				state = isIeee
					? Crc32Arm.Arm64.ComputeCrc32(state, value)
					: BitOperations.Crc32C(state, value);

				sourceRef = ref Unsafe.Add(ref sourceRef, sizeof(ulong));
				length -= sizeof(ulong);
			}
		}

		while (length >= sizeof(uint))
		{
			uint value = Unsafe.ReadUnaligned<uint>(ref sourceRef);
			state = isIeee
				? Crc32Arm.ComputeCrc32(state, value)
				: BitOperations.Crc32C(state, value);

			sourceRef = ref Unsafe.Add(ref sourceRef, sizeof(uint));
			length -= sizeof(uint);
		}

		while (length > 0)
		{
			byte value = sourceRef;
			state = isIeee
				? Crc32Arm.ComputeCrc32(state, value)
				: BitOperations.Crc32C(state, value);

			sourceRef = ref Unsafe.Add(ref sourceRef, 1);
			--length;
		}

		return state;
	}
}
