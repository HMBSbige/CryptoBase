using CryptoBase.Macs.Poly1305;

namespace CryptoBase.Ciphers.Streams;

internal static partial class ChaCha20Utils
{
	private const int Poly1305FusionChunkSize = 1024;

	// The last chunk is hashed alone, so two chunks only break even.
	private const int Poly1305FusionThreshold = 3 * Poly1305FusionChunkSize;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool ShouldFusePoly1305(int length)
	{
		return Vector512.IsHardwareAccelerated && Avx512F.IsSupported && Poly1305Avx512.IsSupported && length >= Poly1305FusionThreshold;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static int XorPoly1305<TState>(ref uint stateRef, ref byte input, ref byte output, int length, ref TState mac) where TState : unmanaged, IPoly1305State<TState>, allows ref struct
	{
		if (typeof(TState) == typeof(Poly1305Avx512))
		{
			return XorVector512Poly1305(ref stateRef, ref input, ref output, length, ref Unsafe.As<TState, Poly1305Avx512>(ref mac));
		}

		Debug.Assert(typeof(TState) == typeof(Poly1305Avx2));
		return XorVector256Poly1305(ref stateRef, ref input, ref output, length, ref Unsafe.As<TState, Poly1305Avx2>(ref mac));
	}

	// Encrypts whole 1 KiB chunks, hashing the previous chunk's ciphertext (unpadded) between the double rounds.
	internal static int XorVector512Poly1305(ref uint stateRef, ref byte input, ref byte output, int length, ref Poly1305Avx512 mac)
	{
		Debug.Assert(length >= Poly1305FusionChunkSize);
		Debug.Assert((uint)length / 64 <= (1UL << 32) - GetCounter(ref stateRef));

		ref ulong counter = ref GetCounterOriginal(ref stateRef);
		int end = length & -Poly1305FusionChunkSize;
		int processed = 0;
		mac.GetEightWayAccumulator(out Vector512<ulong> p0, out Vector512<ulong> p1, out Vector512<ulong> p2, out Vector512<ulong> p3, out Vector512<ulong> p4);

		while (processed < end)
		{
			Vector512<uint> a00 = Vector512.Create(Unsafe.Add(ref stateRef, 0));
			Vector512<uint> a01 = Vector512.Create(Unsafe.Add(ref stateRef, 1));
			Vector512<uint> a02 = Vector512.Create(Unsafe.Add(ref stateRef, 2));
			Vector512<uint> a03 = Vector512.Create(Unsafe.Add(ref stateRef, 3));
			Vector512<uint> a04 = Vector512.Create(Unsafe.Add(ref stateRef, 4));
			Vector512<uint> a05 = Vector512.Create(Unsafe.Add(ref stateRef, 5));
			Vector512<uint> a06 = Vector512.Create(Unsafe.Add(ref stateRef, 6));
			Vector512<uint> a07 = Vector512.Create(Unsafe.Add(ref stateRef, 7));
			Vector512<uint> a08 = Vector512.Create(Unsafe.Add(ref stateRef, 8));
			Vector512<uint> a09 = Vector512.Create(Unsafe.Add(ref stateRef, 9));
			Vector512<uint> a10 = Vector512.Create(Unsafe.Add(ref stateRef, 10));
			Vector512<uint> a11 = Vector512.Create(Unsafe.Add(ref stateRef, 11));
			Vector512<uint> a12 = Vector512.Create((uint)counter) + Vector512.CreateSequence(0u, 1u);
			Vector512<uint> a13 = Vector512.Create(Unsafe.Add(ref stateRef, 13));
			Vector512<uint> a14 = Vector512.Create(Unsafe.Add(ref stateRef, 14));
			Vector512<uint> a15 = Vector512.Create(Unsafe.Add(ref stateRef, 15));

			for (int round = 0; round < SnuffleCipher.Rounds; round += 2)
			{
				QuarterRound(ref a00, ref a04, ref a08, ref a12);
				QuarterRound(ref a01, ref a05, ref a09, ref a13);
				QuarterRound(ref a02, ref a06, ref a10, ref a14);
				QuarterRound(ref a03, ref a07, ref a11, ref a15);

				// The first eight double rounds each hash one 128-byte group.
				if (processed is not 0 && round < 16)
				{
					Poly1305Avx512.AppendEightWayGroup(ref mac, ref Unsafe.Add(ref output, processed - Poly1305FusionChunkSize + round * 64), ref p0, ref p1, ref p2, ref p3, ref p4);
				}

				QuarterRound(ref a00, ref a05, ref a10, ref a15);
				QuarterRound(ref a01, ref a06, ref a11, ref a12);
				QuarterRound(ref a02, ref a07, ref a08, ref a13);
				QuarterRound(ref a03, ref a04, ref a09, ref a14);
			}

			a00 += Vector512.Create(Unsafe.Add(ref stateRef, 0));
			a01 += Vector512.Create(Unsafe.Add(ref stateRef, 1));
			a02 += Vector512.Create(Unsafe.Add(ref stateRef, 2));
			a03 += Vector512.Create(Unsafe.Add(ref stateRef, 3));
			a04 += Vector512.Create(Unsafe.Add(ref stateRef, 4));
			a05 += Vector512.Create(Unsafe.Add(ref stateRef, 5));
			a06 += Vector512.Create(Unsafe.Add(ref stateRef, 6));
			a07 += Vector512.Create(Unsafe.Add(ref stateRef, 7));
			a08 += Vector512.Create(Unsafe.Add(ref stateRef, 8));
			a09 += Vector512.Create(Unsafe.Add(ref stateRef, 9));
			a10 += Vector512.Create(Unsafe.Add(ref stateRef, 10));
			a11 += Vector512.Create(Unsafe.Add(ref stateRef, 11));
			a12 += Vector512.Create((uint)counter) + Vector512.CreateSequence(0u, 1u);
			a13 += Vector512.Create(Unsafe.Add(ref stateRef, 13));
			a14 += Vector512.Create(Unsafe.Add(ref stateRef, 14));
			a15 += Vector512.Create(Unsafe.Add(ref stateRef, 15));
			VectorTranspose.Transpose(ref a00, ref a01, ref a02, ref a03, ref a04, ref a05, ref a06, ref a07, ref a08, ref a09, ref a10, ref a11, ref a12, ref a13, ref a14, ref a15);
			(a00.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)processed)).StoreUnsafe(ref output, (nuint)processed);
			(a01.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 64))).StoreUnsafe(ref output, (nuint)(processed + 64));
			(a02.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 128))).StoreUnsafe(ref output, (nuint)(processed + 128));
			(a03.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 192))).StoreUnsafe(ref output, (nuint)(processed + 192));
			(a04.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 256))).StoreUnsafe(ref output, (nuint)(processed + 256));
			(a05.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 320))).StoreUnsafe(ref output, (nuint)(processed + 320));
			(a06.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 384))).StoreUnsafe(ref output, (nuint)(processed + 384));
			(a07.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 448))).StoreUnsafe(ref output, (nuint)(processed + 448));
			(a08.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 512))).StoreUnsafe(ref output, (nuint)(processed + 512));
			(a09.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 576))).StoreUnsafe(ref output, (nuint)(processed + 576));
			(a10.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 640))).StoreUnsafe(ref output, (nuint)(processed + 640));
			(a11.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 704))).StoreUnsafe(ref output, (nuint)(processed + 704));
			(a12.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 768))).StoreUnsafe(ref output, (nuint)(processed + 768));
			(a13.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 832))).StoreUnsafe(ref output, (nuint)(processed + 832));
			(a14.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 896))).StoreUnsafe(ref output, (nuint)(processed + 896));
			(a15.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 960))).StoreUnsafe(ref output, (nuint)(processed + 960));
			counter += 16;
			processed += Poly1305FusionChunkSize;
		}

		mac.FinishEightWay(ref Unsafe.Add(ref output, processed - Poly1305FusionChunkSize), Poly1305FusionChunkSize, p0, p1, p2, p3, p4);
		return processed;
	}
}
