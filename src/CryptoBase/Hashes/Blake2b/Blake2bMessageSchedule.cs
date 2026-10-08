using static CryptoBase.Hashes.Blake2b.Blake2bCore;

namespace CryptoBase.Hashes.Blake2b;

[InlineArray(Length)]
internal struct Blake2bMessageSchedule
{
	internal const int Length = Rounds * 8;

	private Vector128<ulong> _element;

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void Build(ref Vector128<ulong> schedule, ref byte block)
	{
		Debug.Assert(Sse2.IsSupported);

		Unsafe.Add(ref schedule, 0) = LoadPair(ref block, 0, 2);
		Unsafe.Add(ref schedule, 1) = LoadPair(ref block, 4, 6);
		Unsafe.Add(ref schedule, 2) = LoadPair(ref block, 1, 3);
		Unsafe.Add(ref schedule, 3) = LoadPair(ref block, 5, 7);
		Unsafe.Add(ref schedule, 4) = LoadPair(ref block, 14, 8);
		Unsafe.Add(ref schedule, 5) = LoadPair(ref block, 10, 12);
		Unsafe.Add(ref schedule, 6) = LoadPair(ref block, 15, 9);
		Unsafe.Add(ref schedule, 7) = LoadPair(ref block, 11, 13);

		Unsafe.Add(ref schedule, 8) = LoadPair(ref block, 14, 4);
		Unsafe.Add(ref schedule, 9) = LoadPair(ref block, 9, 13);
		Unsafe.Add(ref schedule, 10) = LoadPair(ref block, 10, 8);
		Unsafe.Add(ref schedule, 11) = LoadPair(ref block, 15, 6);
		Unsafe.Add(ref schedule, 12) = LoadPair(ref block, 5, 1);
		Unsafe.Add(ref schedule, 13) = LoadPair(ref block, 0, 11);
		Unsafe.Add(ref schedule, 14) = LoadPair(ref block, 3, 12);
		Unsafe.Add(ref schedule, 15) = LoadPair(ref block, 2, 7);

		Unsafe.Add(ref schedule, 16) = LoadPair(ref block, 11, 12);
		Unsafe.Add(ref schedule, 17) = LoadPair(ref block, 5, 15);
		Unsafe.Add(ref schedule, 18) = LoadPair(ref block, 8, 0);
		Unsafe.Add(ref schedule, 19) = LoadPair(ref block, 2, 13);
		Unsafe.Add(ref schedule, 20) = LoadPair(ref block, 9, 10);
		Unsafe.Add(ref schedule, 21) = LoadPair(ref block, 3, 7);
		Unsafe.Add(ref schedule, 22) = LoadPair(ref block, 4, 14);
		Unsafe.Add(ref schedule, 23) = LoadPair(ref block, 6, 1);

		Unsafe.Add(ref schedule, 24) = LoadPair(ref block, 7, 3);
		Unsafe.Add(ref schedule, 25) = LoadPair(ref block, 13, 11);
		Unsafe.Add(ref schedule, 26) = LoadPair(ref block, 9, 1);
		Unsafe.Add(ref schedule, 27) = LoadPair(ref block, 12, 14);
		Unsafe.Add(ref schedule, 28) = LoadPair(ref block, 15, 2);
		Unsafe.Add(ref schedule, 29) = LoadPair(ref block, 5, 4);
		Unsafe.Add(ref schedule, 30) = LoadPair(ref block, 8, 6);
		Unsafe.Add(ref schedule, 31) = LoadPair(ref block, 10, 0);

		Unsafe.Add(ref schedule, 32) = LoadPair(ref block, 9, 5);
		Unsafe.Add(ref schedule, 33) = LoadPair(ref block, 2, 10);
		Unsafe.Add(ref schedule, 34) = LoadPair(ref block, 0, 7);
		Unsafe.Add(ref schedule, 35) = LoadPair(ref block, 4, 15);
		Unsafe.Add(ref schedule, 36) = LoadPair(ref block, 3, 14);
		Unsafe.Add(ref schedule, 37) = LoadPair(ref block, 11, 6);
		Unsafe.Add(ref schedule, 38) = LoadPair(ref block, 13, 1);
		Unsafe.Add(ref schedule, 39) = LoadPair(ref block, 12, 8);

		Unsafe.Add(ref schedule, 40) = LoadPair(ref block, 2, 6);
		Unsafe.Add(ref schedule, 41) = LoadPair(ref block, 0, 8);
		Unsafe.Add(ref schedule, 42) = LoadPair(ref block, 12, 10);
		Unsafe.Add(ref schedule, 43) = LoadPair(ref block, 11, 3);
		Unsafe.Add(ref schedule, 44) = LoadPair(ref block, 1, 4);
		Unsafe.Add(ref schedule, 45) = LoadPair(ref block, 7, 15);
		Unsafe.Add(ref schedule, 46) = LoadPair(ref block, 9, 13);
		Unsafe.Add(ref schedule, 47) = LoadPair(ref block, 5, 14);

		Unsafe.Add(ref schedule, 48) = LoadPair(ref block, 12, 1);
		Unsafe.Add(ref schedule, 49) = LoadPair(ref block, 14, 4);
		Unsafe.Add(ref schedule, 50) = LoadPair(ref block, 5, 15);
		Unsafe.Add(ref schedule, 51) = LoadPair(ref block, 13, 10);
		Unsafe.Add(ref schedule, 52) = LoadPair(ref block, 8, 0);
		Unsafe.Add(ref schedule, 53) = LoadPair(ref block, 6, 9);
		Unsafe.Add(ref schedule, 54) = LoadPair(ref block, 11, 7);
		Unsafe.Add(ref schedule, 55) = LoadPair(ref block, 3, 2);

		Unsafe.Add(ref schedule, 56) = LoadPair(ref block, 13, 7);
		Unsafe.Add(ref schedule, 57) = LoadPair(ref block, 12, 3);
		Unsafe.Add(ref schedule, 58) = LoadPair(ref block, 11, 14);
		Unsafe.Add(ref schedule, 59) = LoadPair(ref block, 1, 9);
		Unsafe.Add(ref schedule, 60) = LoadPair(ref block, 2, 5);
		Unsafe.Add(ref schedule, 61) = LoadPair(ref block, 15, 8);
		Unsafe.Add(ref schedule, 62) = LoadPair(ref block, 10, 0);
		Unsafe.Add(ref schedule, 63) = LoadPair(ref block, 4, 6);

		Unsafe.Add(ref schedule, 64) = LoadPair(ref block, 6, 14);
		Unsafe.Add(ref schedule, 65) = LoadPair(ref block, 11, 0);
		Unsafe.Add(ref schedule, 66) = LoadPair(ref block, 15, 9);
		Unsafe.Add(ref schedule, 67) = LoadPair(ref block, 3, 8);
		Unsafe.Add(ref schedule, 68) = LoadPair(ref block, 10, 12);
		Unsafe.Add(ref schedule, 69) = LoadPair(ref block, 13, 1);
		Unsafe.Add(ref schedule, 70) = LoadPair(ref block, 5, 2);
		Unsafe.Add(ref schedule, 71) = LoadPair(ref block, 7, 4);

		Unsafe.Add(ref schedule, 72) = LoadPair(ref block, 10, 8);
		Unsafe.Add(ref schedule, 73) = LoadPair(ref block, 7, 1);
		Unsafe.Add(ref schedule, 74) = LoadPair(ref block, 2, 4);
		Unsafe.Add(ref schedule, 75) = LoadPair(ref block, 6, 5);
		Unsafe.Add(ref schedule, 76) = LoadPair(ref block, 13, 15);
		Unsafe.Add(ref schedule, 77) = LoadPair(ref block, 9, 3);
		Unsafe.Add(ref schedule, 78) = LoadPair(ref block, 0, 11);
		Unsafe.Add(ref schedule, 79) = LoadPair(ref block, 14, 12);

		Unsafe.Add(ref schedule, 80) = LoadPair(ref block, 0, 2);
		Unsafe.Add(ref schedule, 81) = LoadPair(ref block, 4, 6);
		Unsafe.Add(ref schedule, 82) = LoadPair(ref block, 1, 3);
		Unsafe.Add(ref schedule, 83) = LoadPair(ref block, 5, 7);
		Unsafe.Add(ref schedule, 84) = LoadPair(ref block, 14, 8);
		Unsafe.Add(ref schedule, 85) = LoadPair(ref block, 10, 12);
		Unsafe.Add(ref schedule, 86) = LoadPair(ref block, 15, 9);
		Unsafe.Add(ref schedule, 87) = LoadPair(ref block, 11, 13);

		Unsafe.Add(ref schedule, 88) = LoadPair(ref block, 14, 4);
		Unsafe.Add(ref schedule, 89) = LoadPair(ref block, 9, 13);
		Unsafe.Add(ref schedule, 90) = LoadPair(ref block, 10, 8);
		Unsafe.Add(ref schedule, 91) = LoadPair(ref block, 15, 6);
		Unsafe.Add(ref schedule, 92) = LoadPair(ref block, 5, 1);
		Unsafe.Add(ref schedule, 93) = LoadPair(ref block, 0, 11);
		Unsafe.Add(ref schedule, 94) = LoadPair(ref block, 3, 12);
		Unsafe.Add(ref schedule, 95) = LoadPair(ref block, 2, 7);
	}

	// Returns (message[first], message[second]).
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static Vector128<ulong> LoadPair(ref byte block, int first, int second)
	{
		Vector128<ulong> left = Vector128.LoadUnsafe(ref block, (nuint)(first >> 1) * 16).AsUInt64();

		if ((first & 1) is 0 && second == first + 1)
		{
			return left;
		}

		Vector128<ulong> right = Vector128.LoadUnsafe(ref block, (nuint)(second >> 1) * 16).AsUInt64();

		if ((first & 1) is 0)
		{
			return (second & 1) is 0 ? Sse2.UnpackLow(left, right) : Sse2.Shuffle(left.AsDouble(), right.AsDouble(), 0b10).AsUInt64();
		}

		return (second & 1) is 0 ? Sse2.Shuffle(left.AsDouble(), right.AsDouble(), 0b01).AsUInt64() : Sse2.UnpackHigh(left, right);
	}
}
