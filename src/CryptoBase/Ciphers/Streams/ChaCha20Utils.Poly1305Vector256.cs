using CryptoBase.Macs.Poly1305;

namespace CryptoBase.Ciphers.Streams;

internal static partial class ChaCha20Utils
{
	private const int Poly1305ScalarChunkSize = 512;
	private const int Poly1305ScalarThreshold = 1024;
	private const int Poly1305ScalarBlocksPerDoubleRound = 2;
	private const int Poly1305ScalarBytesPerDoubleRound = Poly1305ScalarBlocksPerDoubleRound * Poly1305Algorithm.BlockSizeInBytes;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool ShouldFusePoly1305Scalar(int length)
	{
		return X86Base.X64.IsSupported && Vector256.IsHardwareAccelerated && !Vector512.IsHardwareAccelerated && Poly1305Avx2.IsSupported && length >= Poly1305ScalarThreshold;
	}

	// Encrypts whole 512-byte chunks with AVX2 while the scalar multiplier hashes the ciphertext written so far.
	// The scalar hash lags behind, so the caller's vector state hashes what is left.
	internal static int XorVector256Poly1305(ref uint stateRef, ref byte input, ref byte output, int length, ref Poly1305Avx2 mac)
	{
		Debug.Assert(length >= Poly1305ScalarChunkSize);
		Debug.Assert((uint)length / 64 <= (1UL << 32) - GetCounter(ref stateRef));

		ref ulong counter = ref GetCounterOriginal(ref stateRef);
		int end = length & -Poly1305ScalarChunkSize;
		int processed = 0;
		int hashed = 0;
		mac.GetScalarState(out ulong h0, out ulong h1, out ulong h2, out ulong r0, out ulong r1);
		ulong s1 = r1 + (r1 >> 2);

		while (processed < end)
		{
			Vector256<uint> a00 = Vector256.Create(Unsafe.Add(ref stateRef, 0));
			Vector256<uint> a01 = Vector256.Create(Unsafe.Add(ref stateRef, 1));
			Vector256<uint> a02 = Vector256.Create(Unsafe.Add(ref stateRef, 2));
			Vector256<uint> a03 = Vector256.Create(Unsafe.Add(ref stateRef, 3));
			Vector256<uint> a04 = Vector256.Create(Unsafe.Add(ref stateRef, 4));
			Vector256<uint> a05 = Vector256.Create(Unsafe.Add(ref stateRef, 5));
			Vector256<uint> a06 = Vector256.Create(Unsafe.Add(ref stateRef, 6));
			Vector256<uint> a07 = Vector256.Create(Unsafe.Add(ref stateRef, 7));
			Vector256<uint> a08 = Vector256.Create(Unsafe.Add(ref stateRef, 8));
			Vector256<uint> a09 = Vector256.Create(Unsafe.Add(ref stateRef, 9));
			Vector256<uint> a10 = Vector256.Create(Unsafe.Add(ref stateRef, 10));
			Vector256<uint> a11 = Vector256.Create(Unsafe.Add(ref stateRef, 11));
			Vector256<uint> a12 = Vector256.Create((uint)counter) + Vector256.CreateSequence(0u, 1u);
			Vector256<uint> a13 = Vector256.Create(Unsafe.Add(ref stateRef, 13));
			Vector256<uint> a14 = Vector256.Create(Unsafe.Add(ref stateRef, 14));
			Vector256<uint> a15 = Vector256.Create(Unsafe.Add(ref stateRef, 15));

			for (int round = 0; round < SnuffleCipher.Rounds; round += 2)
			{
				QuarterRound(ref a00, ref a04, ref a08, ref a12);
				QuarterRound(ref a01, ref a05, ref a09, ref a13);
				QuarterRound(ref a02, ref a06, ref a10, ref a14);
				QuarterRound(ref a03, ref a07, ref a11, ref a15);

				if (processed - hashed >= Poly1305ScalarBytesPerDoubleRound)
				{
					Poly1305Software.Block(ref h0, ref h1, ref h2, r0, r1, s1, ref Unsafe.Add(ref output, hashed), Poly1305Software.FullBlockHighBit);
					Poly1305Software.Block(ref h0, ref h1, ref h2, r0, r1, s1, ref Unsafe.Add(ref output, hashed + 16), Poly1305Software.FullBlockHighBit);

					hashed += Poly1305ScalarBytesPerDoubleRound;
				}

				QuarterRound(ref a00, ref a05, ref a10, ref a15);
				QuarterRound(ref a01, ref a06, ref a11, ref a12);
				QuarterRound(ref a02, ref a07, ref a08, ref a13);
				QuarterRound(ref a03, ref a04, ref a09, ref a14);
			}

			a00 += Vector256.Create(Unsafe.Add(ref stateRef, 0));
			a01 += Vector256.Create(Unsafe.Add(ref stateRef, 1));
			a02 += Vector256.Create(Unsafe.Add(ref stateRef, 2));
			a03 += Vector256.Create(Unsafe.Add(ref stateRef, 3));
			a04 += Vector256.Create(Unsafe.Add(ref stateRef, 4));
			a05 += Vector256.Create(Unsafe.Add(ref stateRef, 5));
			a06 += Vector256.Create(Unsafe.Add(ref stateRef, 6));
			a07 += Vector256.Create(Unsafe.Add(ref stateRef, 7));
			a08 += Vector256.Create(Unsafe.Add(ref stateRef, 8));
			a09 += Vector256.Create(Unsafe.Add(ref stateRef, 9));
			a10 += Vector256.Create(Unsafe.Add(ref stateRef, 10));
			a11 += Vector256.Create(Unsafe.Add(ref stateRef, 11));
			a12 += Vector256.Create((uint)counter) + Vector256.CreateSequence(0u, 1u);
			a13 += Vector256.Create(Unsafe.Add(ref stateRef, 13));
			a14 += Vector256.Create(Unsafe.Add(ref stateRef, 14));
			a15 += Vector256.Create(Unsafe.Add(ref stateRef, 15));
			VectorTranspose.Transpose(ref a00, ref a01, ref a02, ref a03, ref a04, ref a05, ref a06, ref a07, ref a08, ref a09, ref a10, ref a11, ref a12, ref a13, ref a14, ref a15);
			(a00.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)processed)).StoreUnsafe(ref output, (nuint)processed);
			(a01.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 32))).StoreUnsafe(ref output, (nuint)(processed + 32));
			(a02.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 64))).StoreUnsafe(ref output, (nuint)(processed + 64));
			(a03.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 96))).StoreUnsafe(ref output, (nuint)(processed + 96));
			(a04.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 128))).StoreUnsafe(ref output, (nuint)(processed + 128));
			(a05.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 160))).StoreUnsafe(ref output, (nuint)(processed + 160));
			(a06.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 192))).StoreUnsafe(ref output, (nuint)(processed + 192));
			(a07.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 224))).StoreUnsafe(ref output, (nuint)(processed + 224));
			(a08.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 256))).StoreUnsafe(ref output, (nuint)(processed + 256));
			(a09.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 288))).StoreUnsafe(ref output, (nuint)(processed + 288));
			(a10.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 320))).StoreUnsafe(ref output, (nuint)(processed + 320));
			(a11.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 352))).StoreUnsafe(ref output, (nuint)(processed + 352));
			(a12.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 384))).StoreUnsafe(ref output, (nuint)(processed + 384));
			(a13.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 416))).StoreUnsafe(ref output, (nuint)(processed + 416));
			(a14.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 448))).StoreUnsafe(ref output, (nuint)(processed + 448));
			(a15.AsByte() ^ Vector256.LoadUnsafe(ref input, (nuint)(processed + 480))).StoreUnsafe(ref output, (nuint)(processed + 480));
			counter += 8;
			processed += Poly1305ScalarChunkSize;
		}

		mac.SetScalarAccumulator(h0, h1, h2);
		mac.AppendMessage(MemoryMarshal.CreateReadOnlySpan(ref Unsafe.Add(ref output, hashed), processed - hashed));
		return processed;
	}
}
