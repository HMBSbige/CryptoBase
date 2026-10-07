using CryptoBase.Ciphers.Blocks.Aes;
using AesArm = System.Runtime.Intrinsics.Arm.Aes;

namespace CryptoBase.Ciphers.Modes.Ccm;

// The state is the MAC XORed with the last round key, which folds into the next first round key, so no EOR separates
// the rounds of consecutive blocks.
internal readonly ref struct AesArmCcmBlockEncryptor : ICcmBlockEncryptor
{
	private readonly ref readonly AesKeys _keys;
	private readonly ref readonly Vector128<byte> _lastKey;
	private readonly int _roundKeyCount;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal AesArmCcmBlockEncryptor(ref readonly AesCipherArm aes)
	{
		_keys = ref aes.RoundKeys;
		_roundKeyCount = aes.RoundKeyCount;
		_lastKey = ref Unsafe.Add(ref Unsafe.AsRef(in _keys.K0), _roundKeyCount - 1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Begin(ref Vector128<byte> state, ref Vector128<byte> counterBlock)
	{
		EncryptRounds(ref state, _keys.K0, ref counterBlock, _keys.K0);
		counterBlock ^= _lastKey;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Absorb(ref Vector128<byte> state, Vector128<byte> block)
	{
		state = EncryptRounds(state, block ^ _keys.K0 ^ _lastKey);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Absorb(ref Vector128<byte> state, Vector128<byte> block, ref Vector128<byte> counterBlock)
	{
		EncryptRounds(ref state, block ^ _keys.K0 ^ _lastKey, ref counterBlock, _keys.K0);
		counterBlock ^= _lastKey;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public Vector128<byte> Finish(Vector128<byte> state)
	{
		return state ^ _lastKey;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private Vector128<byte> EncryptRounds(Vector128<byte> state, Vector128<byte> firstKey)
	{
		ref readonly AesKeys keys = ref _keys;

		state = Round(state, firstKey);
		state = Round(state, keys.K1);
		state = Round(state, keys.K2);
		state = Round(state, keys.K3);
		state = Round(state, keys.K4);
		state = Round(state, keys.K5);
		state = Round(state, keys.K6);
		state = Round(state, keys.K7);
		state = Round(state, keys.K8);

		if (_roundKeyCount > 11)
		{
			state = Round(state, keys.K9);
			state = Round(state, keys.K10);

			if (_roundKeyCount > 13)
			{
				state = Round(state, keys.K11);
				state = Round(state, keys.K12);
			}
		}

		return AesArm.Encrypt(state, Unsafe.Subtract(ref Unsafe.AsRef(in _lastKey), 1));

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static Vector128<byte> Round(Vector128<byte> state, Vector128<byte> key)
		{
			return AesArm.MixColumns(AesArm.Encrypt(state, key));
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void EncryptRounds(ref Vector128<byte> v0, Vector128<byte> firstKey0, ref Vector128<byte> v1, Vector128<byte> firstKey1)
	{
		ref readonly AesKeys keys = ref _keys;

		v0 = AesArm.MixColumns(AesArm.Encrypt(v0, firstKey0));
		v1 = AesArm.MixColumns(AesArm.Encrypt(v1, firstKey1));
		Round(ref v0, ref v1, keys.K1);
		Round(ref v0, ref v1, keys.K2);
		Round(ref v0, ref v1, keys.K3);
		Round(ref v0, ref v1, keys.K4);
		Round(ref v0, ref v1, keys.K5);
		Round(ref v0, ref v1, keys.K6);
		Round(ref v0, ref v1, keys.K7);
		Round(ref v0, ref v1, keys.K8);

		if (_roundKeyCount > 11)
		{
			Round(ref v0, ref v1, keys.K9);
			Round(ref v0, ref v1, keys.K10);

			if (_roundKeyCount > 13)
			{
				Round(ref v0, ref v1, keys.K11);
				Round(ref v0, ref v1, keys.K12);
			}
		}

		Vector128<byte> finalKey = Unsafe.Subtract(ref Unsafe.AsRef(in _lastKey), 1);
		v0 = AesArm.Encrypt(v0, finalKey);
		v1 = AesArm.Encrypt(v1, finalKey);

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void Round(ref Vector128<byte> v0, ref Vector128<byte> v1, Vector128<byte> key)
		{
			v0 = AesArm.MixColumns(AesArm.Encrypt(v0, key));
			v1 = AesArm.MixColumns(AesArm.Encrypt(v1, key));
		}
	}
}
