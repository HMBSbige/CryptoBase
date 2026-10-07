using CryptoBase.Ciphers.Blocks.Aes;
using AesX86 = System.Runtime.Intrinsics.X86.Aes;

namespace CryptoBase.Ciphers.Modes.Ccm;

// Each chain encryption finishes only when the next block arrives, which folds into its last round key.
// The state is therefore the next cipher input XORed with K0, and no XOR separates the rounds of consecutive blocks.
internal readonly ref struct AesX86CcmBlockEncryptor : ICcmBlockEncryptor
{
	private readonly ref readonly AesKeys _keys;
	private readonly ref readonly Vector128<byte> _lastKey;
	private readonly int _roundKeyCount;

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal AesX86CcmBlockEncryptor(ref readonly AesCipherX86 aes)
	{
		_keys = ref aes.RoundKeys;
		_roundKeyCount = aes.RoundKeyCount;
		_lastKey = ref Unsafe.Add(ref Unsafe.AsRef(in _keys.K0), _roundKeyCount - 1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Begin(ref Vector128<byte> state, ref Vector128<byte> counterBlock)
	{
		counterBlock = EncryptRounds(counterBlock ^ _keys.K0, _lastKey);
		state ^= _keys.K0;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Absorb(ref Vector128<byte> state, Vector128<byte> block)
	{
		state = EncryptRounds(state, block ^ _keys.K0 ^ _lastKey);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Absorb(ref Vector128<byte> state, Vector128<byte> block, ref Vector128<byte> counterBlock)
	{
		counterBlock ^= _keys.K0;
		EncryptRounds(ref state, block ^ _keys.K0 ^ _lastKey, ref counterBlock, _lastKey);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public Vector128<byte> Finish(Vector128<byte> state)
	{
		return EncryptRounds(state, _lastKey);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private Vector128<byte> EncryptRounds(Vector128<byte> state, Vector128<byte> lastKey)
	{
		ref readonly AesKeys keys = ref _keys;

		state = AesX86.Encrypt(state, keys.K1);
		state = AesX86.Encrypt(state, keys.K2);
		state = AesX86.Encrypt(state, keys.K3);
		state = AesX86.Encrypt(state, keys.K4);
		state = AesX86.Encrypt(state, keys.K5);
		state = AesX86.Encrypt(state, keys.K6);
		state = AesX86.Encrypt(state, keys.K7);
		state = AesX86.Encrypt(state, keys.K8);
		state = AesX86.Encrypt(state, keys.K9);

		if (_roundKeyCount > 11)
		{
			state = AesX86.Encrypt(state, keys.K10);
			state = AesX86.Encrypt(state, keys.K11);

			if (_roundKeyCount > 13)
			{
				state = AesX86.Encrypt(state, keys.K12);
				state = AesX86.Encrypt(state, keys.K13);
			}
		}

		return AesX86.EncryptLast(state, lastKey);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void EncryptRounds(ref Vector128<byte> v0, Vector128<byte> lastKey0, ref Vector128<byte> v1, Vector128<byte> lastKey1)
	{
		ref readonly AesKeys keys = ref _keys;

		Round(ref v0, ref v1, keys.K1);
		Round(ref v0, ref v1, keys.K2);
		Round(ref v0, ref v1, keys.K3);
		Round(ref v0, ref v1, keys.K4);
		Round(ref v0, ref v1, keys.K5);
		Round(ref v0, ref v1, keys.K6);
		Round(ref v0, ref v1, keys.K7);
		Round(ref v0, ref v1, keys.K8);
		Round(ref v0, ref v1, keys.K9);

		if (_roundKeyCount > 11)
		{
			Round(ref v0, ref v1, keys.K10);
			Round(ref v0, ref v1, keys.K11);

			if (_roundKeyCount > 13)
			{
				Round(ref v0, ref v1, keys.K12);
				Round(ref v0, ref v1, keys.K13);
			}
		}

		v0 = AesX86.EncryptLast(v0, lastKey0);
		v1 = AesX86.EncryptLast(v1, lastKey1);

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void Round(ref Vector128<byte> v0, ref Vector128<byte> v1, Vector128<byte> key)
		{
			v0 = AesX86.Encrypt(v0, key);
			v1 = AesX86.Encrypt(v1, key);
		}
	}
}
