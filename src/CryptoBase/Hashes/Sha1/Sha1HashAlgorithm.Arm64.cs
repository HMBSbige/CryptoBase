using Sha1Arm = System.Runtime.Intrinsics.Arm.Sha1;

namespace CryptoBase.Hashes.Sha1;

public partial struct Sha1HashAlgorithm
{
	private static void ProcessBlocksArm64(ref Sha1HashAlgorithm hashAlgorithm, ReadOnlySpan<byte> source)
	{
		Debug.Assert(Sha1Arm.Arm64.IsSupported);

		ref uint firstStateWord = ref hashAlgorithm._h0;
		Vector128<uint> stateAbcd = Vector128.LoadUnsafe(ref firstStateWord);
		Vector64<uint> stateE = Vector64.CreateScalar(hashAlgorithm._h4);
		ref byte block = ref source.GetReference();
		int remainingLength = source.Length;

		do
		{
			ProcessBlockArm64(ref stateAbcd, ref stateE, ref block);
			block = ref Unsafe.Add(ref block, BlockSizeInBytes);
			remainingLength -= BlockSizeInBytes;
		} while (remainingLength is not 0);

		stateAbcd.StoreUnsafe(ref firstStateWord);
		hashAlgorithm._h4 = stateE.ToScalar();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ProcessBlockArm64(ref Vector128<uint> stateAbcd, ref Vector64<uint> stateE, ref byte block)
	{
		Vector128<uint> words0 = LoadArm64Words(ref block);
		Vector128<uint> words1 = LoadArm64Words(ref Unsafe.Add(ref block, 16));
		Vector128<uint> words2 = LoadArm64Words(ref Unsafe.Add(ref block, 32));
		Vector128<uint> words3 = LoadArm64Words(ref Unsafe.Add(ref block, 48));
		Vector128<uint> savedStateAbcd = stateAbcd;
		Vector64<uint> savedStateE = stateE;
		Vector128<uint> chooseConstants = Vector128.Create(ChooseConstant);
		Vector128<uint> parityConstants1 = Vector128.Create(ParityConstant1);
		Vector128<uint> majorityConstants = Vector128.Create(MajorityConstant);
		Vector128<uint> parityConstants2 = Vector128.Create(ParityConstant2);

		ChooseRoundArm64(ref stateAbcd, ref stateE, words0 + chooseConstants);
		words0 = UpdateArm64Schedule(words0, words1, words2, words3);
		ChooseRoundArm64(ref stateAbcd, ref stateE, words1 + chooseConstants);
		words1 = UpdateArm64Schedule(words1, words2, words3, words0);
		ChooseRoundArm64(ref stateAbcd, ref stateE, words2 + chooseConstants);
		words2 = UpdateArm64Schedule(words2, words3, words0, words1);
		ChooseRoundArm64(ref stateAbcd, ref stateE, words3 + chooseConstants);
		words3 = UpdateArm64Schedule(words3, words0, words1, words2);
		ChooseRoundArm64(ref stateAbcd, ref stateE, words0 + chooseConstants);
		words0 = UpdateArm64Schedule(words0, words1, words2, words3);

		ParityRoundArm64(ref stateAbcd, ref stateE, words1 + parityConstants1);
		words1 = UpdateArm64Schedule(words1, words2, words3, words0);
		ParityRoundArm64(ref stateAbcd, ref stateE, words2 + parityConstants1);
		words2 = UpdateArm64Schedule(words2, words3, words0, words1);
		ParityRoundArm64(ref stateAbcd, ref stateE, words3 + parityConstants1);
		words3 = UpdateArm64Schedule(words3, words0, words1, words2);
		ParityRoundArm64(ref stateAbcd, ref stateE, words0 + parityConstants1);
		words0 = UpdateArm64Schedule(words0, words1, words2, words3);
		ParityRoundArm64(ref stateAbcd, ref stateE, words1 + parityConstants1);
		words1 = UpdateArm64Schedule(words1, words2, words3, words0);

		MajorityRoundArm64(ref stateAbcd, ref stateE, words2 + majorityConstants);
		words2 = UpdateArm64Schedule(words2, words3, words0, words1);
		MajorityRoundArm64(ref stateAbcd, ref stateE, words3 + majorityConstants);
		words3 = UpdateArm64Schedule(words3, words0, words1, words2);
		MajorityRoundArm64(ref stateAbcd, ref stateE, words0 + majorityConstants);
		words0 = UpdateArm64Schedule(words0, words1, words2, words3);
		MajorityRoundArm64(ref stateAbcd, ref stateE, words1 + majorityConstants);
		words1 = UpdateArm64Schedule(words1, words2, words3, words0);
		MajorityRoundArm64(ref stateAbcd, ref stateE, words2 + majorityConstants);
		words2 = UpdateArm64Schedule(words2, words3, words0, words1);

		ParityRoundArm64(ref stateAbcd, ref stateE, words3 + parityConstants2);
		words3 = UpdateArm64Schedule(words3, words0, words1, words2);
		ParityRoundArm64(ref stateAbcd, ref stateE, words0 + parityConstants2);
		ParityRoundArm64(ref stateAbcd, ref stateE, words1 + parityConstants2);
		ParityRoundArm64(ref stateAbcd, ref stateE, words2 + parityConstants2);
		ParityRoundArm64(ref stateAbcd, ref stateE, words3 + parityConstants2);

		stateAbcd += savedStateAbcd;
		stateE += savedStateE;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> LoadArm64Words(ref byte source)
	{
		return Vector128.LoadUnsafe(ref source).ReverseEndianness32().AsUInt32();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<uint> UpdateArm64Schedule(Vector128<uint> words0, Vector128<uint> words1, Vector128<uint> words2, Vector128<uint> words3)
	{
		Vector128<uint> partial = Sha1Arm.ScheduleUpdate0(words0, words1, words2);
		return Sha1Arm.ScheduleUpdate1(partial, words3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ChooseRoundArm64(ref Vector128<uint> stateAbcd, ref Vector64<uint> stateE, Vector128<uint> roundInput)
	{
		Vector64<uint> previousE = Sha1Arm.FixedRotate(stateAbcd.GetLower());
		stateAbcd = Sha1Arm.HashUpdateChoose(stateAbcd, stateE, roundInput);
		stateE = previousE;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ParityRoundArm64(ref Vector128<uint> stateAbcd, ref Vector64<uint> stateE, Vector128<uint> roundInput)
	{
		Vector64<uint> previousE = Sha1Arm.FixedRotate(stateAbcd.GetLower());
		stateAbcd = Sha1Arm.HashUpdateParity(stateAbcd, stateE, roundInput);
		stateE = previousE;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void MajorityRoundArm64(ref Vector128<uint> stateAbcd, ref Vector64<uint> stateE, Vector128<uint> roundInput)
	{
		Vector64<uint> previousE = Sha1Arm.FixedRotate(stateAbcd.GetLower());
		stateAbcd = Sha1Arm.HashUpdateMajority(stateAbcd, stateE, roundInput);
		stateE = previousE;
	}
}
