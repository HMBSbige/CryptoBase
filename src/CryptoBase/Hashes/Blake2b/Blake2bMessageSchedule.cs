namespace CryptoBase.Hashes.Blake2b;

internal static class Blake2bMessageSchedule
{
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
