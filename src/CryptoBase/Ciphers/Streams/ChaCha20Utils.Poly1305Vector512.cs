using CryptoBase.Ciphers.Modes;
using CryptoBase.Macs.Poly1305;

namespace CryptoBase.Ciphers.Streams;

internal static partial class ChaCha20Utils
{
	// One kernel iteration covers one keystream batch.
	internal const int Poly1305FusionChunkSize = 1024;
	private const int Poly1305EightWayGroupSize = 128;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static bool CanFusePoly1305<TState>() where TState : unmanaged, IPoly1305State<TState>, allows ref struct
	{
		return typeof(TState) == typeof(Poly1305Avx512) && Poly1305Avx512.IsSupported;
	}

	// Runs from processed and returns where it stops; the MAC covers the ciphertext before hashedLength.
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static int XorPoly1305<TState>(ref uint stateRef, ref byte input, ref byte output, int length, ref TState mac, int processed, ref int hashedLength, bool decrypt) where TState : unmanaged, IPoly1305State<TState>, allows ref struct
	{
		Debug.Assert(CanFusePoly1305<TState>() && Poly1305FusionChunkSize == BatchLength);

		ref Poly1305Avx512 state = ref Unsafe.As<TState, Poly1305Avx512>(ref mac);
		return decrypt
			? XorVector512Poly1305<Decryption>(ref stateRef, ref input, ref output, length, ref state, processed, ref hashedLength)
			: XorVector512Poly1305<Encryption>(ref stateRef, ref input, ref output, length, ref state, processed, ref hashedLength);
	}

	// Double rounds interleave 128-byte groups, one Poly1305 block per lane: encryption hashes the ciphertext written before this batch, decryption this batch before storing over it.
	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveOptimization)]
	private static int XorVector512Poly1305<TDirection>(ref uint stateRef, ref byte input, ref byte output, int length, ref Poly1305Avx512 mac, int processed, ref int hashedLength) where TDirection : struct, IBlockDirection
	{
		Debug.Assert(TDirection.IsDecrypt ? hashedLength == processed : hashedLength <= processed);
		Debug.Assert(processed % Poly1305Algorithm.BlockSizeInBytes is 0);
		Debug.Assert((uint)(length - processed + 63) / 64 <= (1UL << 32) - GetCounter(ref stateRef));

		ref ulong counter = ref GetCounterOriginal(ref stateRef);
		int hashed = hashedLength;
		int partial = 0;
		Span<byte> keyStreamBuffer = stackalloc byte[Poly1305FusionChunkSize];
		ref byte keyStream = ref MemoryMarshal.GetReference(keyStreamBuffer);
		mac.GetEightWayAccumulator(out Vector512<ulong> p0, out Vector512<ulong> p1, out Vector512<ulong> p2, out Vector512<ulong> p3, out Vector512<ulong> p4);

		// Decryption takes a final chunk only if it holds two groups: one for FinishEightWay and at least one to hash in the rounds.
		int minimumChunk = TDirection.IsDecrypt ? 2 * Poly1305EightWayGroupSize : 1;

		while (length - processed >= minimumChunk)
		{
			int chunk = Math.Min(length - processed, Poly1305FusionChunkSize);
			int groups = chunk / Poly1305EightWayGroupSize;
			// FinishEightWay takes the last whole group the kernel hashes, so neither direction hashes it in the rounds.
			bool finish = TDirection.IsDecrypt && length - processed - chunk < minimumChunk;
			int groupRounds;

			if (TDirection.IsDecrypt)
			{
				groupRounds = (finish ? groups - 1 : groups) * 2;
			}
			else
			{
				int behind = Math.Min((processed - hashed) / Poly1305EightWayGroupSize, 8);

				if (chunk < Poly1305FusionChunkSize && behind > 0 && length - hashed - behind * Poly1305EightWayGroupSize < Poly1305EightWayGroupSize)
				{
					behind--;
				}

				groupRounds = behind * 2;
			}

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

				if (round < groupRounds)
				{
					Poly1305Avx512.AppendEightWayGroup(ref mac, ref Unsafe.Add(ref TDirection.IsDecrypt ? ref input : ref output, hashed), ref p0, ref p1, ref p2, ref p3, ref p4);
					hashed += Poly1305EightWayGroupSize;
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

			if (chunk < Poly1305FusionChunkSize)
			{
				a00.AsByte().StoreUnsafe(ref keyStream, 0);
				a01.AsByte().StoreUnsafe(ref keyStream, 64);
				a02.AsByte().StoreUnsafe(ref keyStream, 128);
				a03.AsByte().StoreUnsafe(ref keyStream, 192);
				a04.AsByte().StoreUnsafe(ref keyStream, 256);
				a05.AsByte().StoreUnsafe(ref keyStream, 320);
				a06.AsByte().StoreUnsafe(ref keyStream, 384);
				a07.AsByte().StoreUnsafe(ref keyStream, 448);
				a08.AsByte().StoreUnsafe(ref keyStream, 512);
				a09.AsByte().StoreUnsafe(ref keyStream, 576);
				a10.AsByte().StoreUnsafe(ref keyStream, 640);
				a11.AsByte().StoreUnsafe(ref keyStream, 704);
				a12.AsByte().StoreUnsafe(ref keyStream, 768);
				a13.AsByte().StoreUnsafe(ref keyStream, 832);
				a14.AsByte().StoreUnsafe(ref keyStream, 896);
				a15.AsByte().StoreUnsafe(ref keyStream, 960);
				counter += (uint)(chunk + 63) / 64;
				partial = chunk;
				break;
			}

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

			if (finish)
			{
				mac.FinishEightWay(ref Unsafe.Add(ref input, hashed), Poly1305EightWayGroupSize, p0, p1, p2, p3, p4);
				hashed += Poly1305EightWayGroupSize;
			}

			(a14.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 896))).StoreUnsafe(ref output, (nuint)(processed + 896));
			(a15.AsByte() ^ Vector512.LoadUnsafe(ref input, (nuint)(processed + 960))).StoreUnsafe(ref output, (nuint)(processed + 960));
			counter += 16;
			processed += Poly1305FusionChunkSize;
		}

		// A partial final chunk left its keystream in the buffer; decryption hashes the rest of the message before storing over it.
		if (partial > 0)
		{
			if (TDirection.IsDecrypt)
			{
				mac.FinishEightWay(ref Unsafe.Add(ref input, hashed), Poly1305EightWayGroupSize, p0, p1, p2, p3, p4);
				hashed += Poly1305EightWayGroupSize;

				mac.AppendPaddedSegment(MemoryMarshal.CreateReadOnlySpan(ref Unsafe.Add(ref input, hashed), length - hashed));
				hashed = length;
			}

			FastUtils.Xor(keyStreamBuffer, MemoryMarshal.CreateReadOnlySpan(ref Unsafe.Add(ref input, processed), partial), MemoryMarshal.CreateSpan(ref Unsafe.Add(ref output, processed), partial), partial);
			keyStreamBuffer.Clear();
			processed = length;
		}

		// Decryption has closed the lanes already; encryption closes them here with the whole groups still behind, unless the loop hashed nothing.
		if (!TDirection.IsDecrypt && hashed != hashedLength)
		{
			int groups = processed - hashed & -Poly1305EightWayGroupSize;
			mac.FinishEightWay(ref Unsafe.Add(ref output, hashed), groups, p0, p1, p2, p3, p4);
			hashed += groups;
		}

		hashedLength = hashed;
		return processed;
	}
}
