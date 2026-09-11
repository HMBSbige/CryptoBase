using Sha256Arm = System.Runtime.Intrinsics.Arm.Sha256;

namespace CryptoBase.Hashes.Sha256;

internal partial struct Sha256Core
{
	private void ProcessBlocksArm64(ReadOnlySpan<byte> source)
	{
		Debug.Assert(Sha256Arm.Arm64.IsSupported);

		ref uint firstStateWord = ref _h0;
		Vector128<uint> state0 = Vector128.LoadUnsafe(ref firstStateWord);
		Vector128<uint> state1 = Vector128.LoadUnsafe(ref firstStateWord, 4);
		ref byte block = ref source.GetReference();
		int remainingLength = source.Length;

		do
		{
			ProcessBlockArm64(ref state0, ref state1, ref block);
			block = ref Unsafe.Add(ref block, BlockSizeInBytes);
			remainingLength -= BlockSizeInBytes;
		} while (remainingLength is not 0);

		state0.StoreUnsafe(ref firstStateWord);
		state1.StoreUnsafe(ref firstStateWord, 4);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static unsafe void ProcessBlockArm64(ref Vector128<uint> state0, ref Vector128<uint> state1, ref byte block)
	{
		(Vector128<byte> block0, Vector128<byte> block1, Vector128<byte> block2, Vector128<byte> block3) = AdvSimd.Arm64.Load4xVector128((byte*)Unsafe.AsPointer(ref block));
		Vector128<uint> words0 = block0.ReverseEndianness32().AsUInt32();
		Vector128<uint> words1 = block1.ReverseEndianness32().AsUInt32();
		Vector128<uint> words2 = block2.ReverseEndianness32().AsUInt32();
		Vector128<uint> words3 = block3.ReverseEndianness32().AsUInt32();
		Vector128<uint> savedState0 = state0;
		Vector128<uint> savedState1 = state1;
		ref uint roundConstants = ref RoundConstants.GetReference();

		(Vector128<uint> roundConstants0, Vector128<uint> roundConstants1) = LoadArm64RoundConstants(ref roundConstants, 0);
		state0 = RoundArm64(state0, ref state1, words0, roundConstants0);
		words0 = UpdateArm64Schedule(words0, words1, words2, words3);
		state0 = RoundArm64(state0, ref state1, words1, roundConstants1);
		words1 = UpdateArm64Schedule(words1, words2, words3, words0);
		(roundConstants0, roundConstants1) = LoadArm64RoundConstants(ref roundConstants, 8);
		state0 = RoundArm64(state0, ref state1, words2, roundConstants0);
		words2 = UpdateArm64Schedule(words2, words3, words0, words1);
		state0 = RoundArm64(state0, ref state1, words3, roundConstants1);
		words3 = UpdateArm64Schedule(words3, words0, words1, words2);

		(roundConstants0, roundConstants1) = LoadArm64RoundConstants(ref roundConstants, 16);
		state0 = RoundArm64(state0, ref state1, words0, roundConstants0);
		words0 = UpdateArm64Schedule(words0, words1, words2, words3);
		state0 = RoundArm64(state0, ref state1, words1, roundConstants1);
		words1 = UpdateArm64Schedule(words1, words2, words3, words0);
		(roundConstants0, roundConstants1) = LoadArm64RoundConstants(ref roundConstants, 24);
		state0 = RoundArm64(state0, ref state1, words2, roundConstants0);
		words2 = UpdateArm64Schedule(words2, words3, words0, words1);
		state0 = RoundArm64(state0, ref state1, words3, roundConstants1);
		words3 = UpdateArm64Schedule(words3, words0, words1, words2);

		(roundConstants0, roundConstants1) = LoadArm64RoundConstants(ref roundConstants, 32);
		state0 = RoundArm64(state0, ref state1, words0, roundConstants0);
		words0 = UpdateArm64Schedule(words0, words1, words2, words3);
		state0 = RoundArm64(state0, ref state1, words1, roundConstants1);
		words1 = UpdateArm64Schedule(words1, words2, words3, words0);
		(roundConstants0, roundConstants1) = LoadArm64RoundConstants(ref roundConstants, 40);
		state0 = RoundArm64(state0, ref state1, words2, roundConstants0);
		words2 = UpdateArm64Schedule(words2, words3, words0, words1);
		state0 = RoundArm64(state0, ref state1, words3, roundConstants1);
		words3 = UpdateArm64Schedule(words3, words0, words1, words2);

		(roundConstants0, roundConstants1) = LoadArm64RoundConstants(ref roundConstants, 48);
		state0 = RoundArm64(state0, ref state1, words0, roundConstants0);
		state0 = RoundArm64(state0, ref state1, words1, roundConstants1);
		(roundConstants0, roundConstants1) = LoadArm64RoundConstants(ref roundConstants, 56);
		state0 = RoundArm64(state0, ref state1, words2, roundConstants0);
		state0 = RoundArm64(state0, ref state1, words3, roundConstants1);

		state0 += savedState0;
		state1 += savedState1;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> LoadArm64Words(ref byte source)
	{
		return Vector128.LoadUnsafe(ref source).ReverseEndianness32().AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static unsafe (Vector128<uint>, Vector128<uint>) LoadArm64RoundConstants(ref uint source, int offset)
	{
		return AdvSimd.Arm64.LoadPairVector128((uint*)Unsafe.AsPointer(ref Unsafe.Add(ref source, offset)));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> UpdateArm64Schedule(Vector128<uint> words0, Vector128<uint> words1, Vector128<uint> words2, Vector128<uint> words3)
	{
		Vector128<uint> partial = Sha256Arm.ScheduleUpdate0(words0, words1);
		return Sha256Arm.ScheduleUpdate1(partial, words2, words3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> RoundArm64(Vector128<uint> state0, ref Vector128<uint> state1, Vector128<uint> words, Vector128<uint> roundConstants)
	{
		Vector128<uint> previousState0 = state0;
		Vector128<uint> roundInput = words + roundConstants;
		state0 = Sha256Arm.HashUpdate1(state0, state1, roundInput);
		state1 = Sha256Arm.HashUpdate2(state1, previousState0, roundInput);
		return state0;
	}
}
