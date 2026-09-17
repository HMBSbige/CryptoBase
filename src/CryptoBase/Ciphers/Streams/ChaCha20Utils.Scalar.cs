namespace CryptoBase.Ciphers.Streams;

internal static partial class ChaCha20Utils
{
	private static int XorScalar(ref uint stateRef, ref byte input, ref byte output, int length)
	{
		int processed = length & -64;

		for (int remaining = processed; remaining > 0; remaining -= 64)
		{
			uint x00 = Unsafe.Add(ref stateRef, 0);
			uint x01 = Unsafe.Add(ref stateRef, 1);
			uint x02 = Unsafe.Add(ref stateRef, 2);
			uint x03 = Unsafe.Add(ref stateRef, 3);
			uint x04 = Unsafe.Add(ref stateRef, 4);
			uint x05 = Unsafe.Add(ref stateRef, 5);
			uint x06 = Unsafe.Add(ref stateRef, 6);
			uint x07 = Unsafe.Add(ref stateRef, 7);
			uint x08 = Unsafe.Add(ref stateRef, 8);
			uint x09 = Unsafe.Add(ref stateRef, 9);
			uint x10 = Unsafe.Add(ref stateRef, 10);
			uint x11 = Unsafe.Add(ref stateRef, 11);
			uint x12 = Unsafe.Add(ref stateRef, 12);
			uint x13 = Unsafe.Add(ref stateRef, 13);
			uint x14 = Unsafe.Add(ref stateRef, 14);
			uint x15 = Unsafe.Add(ref stateRef, 15);

			PermuteScalar(SnuffleCipher.Rounds, ref x00, ref x01, ref x02, ref x03, ref x04, ref x05, ref x06, ref x07, ref x08, ref x09, ref x10, ref x11, ref x12, ref x13, ref x14, ref x15);

			Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 0), x00 + Unsafe.Add(ref stateRef, 0) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref input, 0)));
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 4), x01 + Unsafe.Add(ref stateRef, 1) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref input, 4)));
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 8), x02 + Unsafe.Add(ref stateRef, 2) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref input, 8)));
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 12), x03 + Unsafe.Add(ref stateRef, 3) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref input, 12)));
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 16), x04 + Unsafe.Add(ref stateRef, 4) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref input, 16)));
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 20), x05 + Unsafe.Add(ref stateRef, 5) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref input, 20)));
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 24), x06 + Unsafe.Add(ref stateRef, 6) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref input, 24)));
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 28), x07 + Unsafe.Add(ref stateRef, 7) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref input, 28)));
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 32), x08 + Unsafe.Add(ref stateRef, 8) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref input, 32)));
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 36), x09 + Unsafe.Add(ref stateRef, 9) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref input, 36)));
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 40), x10 + Unsafe.Add(ref stateRef, 10) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref input, 40)));
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 44), x11 + Unsafe.Add(ref stateRef, 11) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref input, 44)));
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 48), x12 + Unsafe.Add(ref stateRef, 12) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref input, 48)));
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 52), x13 + Unsafe.Add(ref stateRef, 13) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref input, 52)));
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 56), x14 + Unsafe.Add(ref stateRef, 14) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref input, 56)));
			Unsafe.WriteUnaligned(ref Unsafe.Add(ref output, 60), x15 + Unsafe.Add(ref stateRef, 15) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref input, 60)));

			++GetCounterOriginal(ref stateRef);
			input = ref Unsafe.Add(ref input, 64);
			output = ref Unsafe.Add(ref output, 64);
		}

		return processed;
	}
}
