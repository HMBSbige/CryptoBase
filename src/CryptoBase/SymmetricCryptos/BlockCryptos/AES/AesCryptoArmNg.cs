namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

internal readonly struct AesCryptoArmNg : IBlock16Crypto<AesCryptoArmNg>
{
	public static bool IsSupported => AesArm.IsSupported;

	private readonly int _keyLength;

	private readonly AesKeys _roundKeys;
	private readonly AesKeys _reverseRoundKeys;

	public void Dispose()
	{
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private AesCryptoArmNg(in ReadOnlySpan<byte> key)
	{
		_keyLength = key.Length switch
		{
			16 => 11,
			24 => 13,
			32 => 15,
			_ => ThrowHelper.ThrowArgumentOutOfRangeException<int>(nameof(key), "Key length must be 16/24/32 bytes")
		};

		int sizeOfuint = _keyLength * 4;
		Span<uint> keys = MemoryMarshal.CreateSpan(ref Unsafe.As<AesKeys, uint>(ref _roundKeys), sizeOfuint);
		key.CopyTo(MemoryMarshal.AsBytes(keys));

		int nk = key.Length / sizeof(uint);

		for (int i = nk; i < sizeOfuint; ++i)
		{
			uint t = keys[i - 1];

			if (i % nk is 0)
			{
				t = SubWord(t).RotateRight(8) ^ AesCryptoNg.Rcon[i / nk];
			}
			else if (nk > 6 && i % nk is 4)
			{
				t = SubWord(t);
			}

			keys[i] = keys[i - nk] ^ t;
		}

		InverseExpandedKey(
			MemoryMarshal.CreateReadOnlySpan(ref Unsafe.As<AesKeys, Vector128<byte>>(ref _roundKeys), _keyLength),
			MemoryMarshal.CreateSpan(ref Unsafe.As<AesKeys, Vector128<byte>>(ref _reverseRoundKeys), _keyLength)
		);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseExpandedKey(ReadOnlySpan<Vector128<byte>> roundKeys, Span<Vector128<byte>> inverseKey)
	{
		Debug.Assert(roundKeys.Length is 11 or 13 or 15 && inverseKey.Length == roundKeys.Length);

		inverseKey[0] = roundKeys[^1];
		inverseKey[^1] = roundKeys[0];

		for (int i = 1; i < roundKeys.Length - 1; ++i)
		{
			inverseKey[i] = AesArm.InverseMixColumns(roundKeys[^(1 + i)]);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint SubWord(uint x)
	{
		return AesArm.Encrypt(Vector128.Create(x).AsByte(), Vector128<byte>.Zero).AsUInt32().ToScalar();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void EncryptPart(ref Vector128<byte> state, in Vector128<byte> key)
	{
		state = AesArm.MixColumns(AesArm.Encrypt(state, key));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void DecryptPart(ref Vector128<byte> state, in Vector128<byte> key)
	{
		state = AesArm.InverseMixColumns(AesArm.Decrypt(state, key));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static AesCryptoArmNg Create(in ReadOnlySpan<byte> key)
	{
		return new AesCryptoArmNg(key);
	}

	public VectorBuffer16 Encrypt(scoped in VectorBuffer16 source)
	{
		VectorBuffer16 value = source;

		ref readonly AesKeys keys = ref _roundKeys;

		EncryptPart(ref value.V128, keys.K0);
		EncryptPart(ref value.V128, keys.K1);
		EncryptPart(ref value.V128, keys.K2);
		EncryptPart(ref value.V128, keys.K3);
		EncryptPart(ref value.V128, keys.K4);
		EncryptPart(ref value.V128, keys.K5);
		EncryptPart(ref value.V128, keys.K6);
		EncryptPart(ref value.V128, keys.K7);
		EncryptPart(ref value.V128, keys.K8);

		if (_keyLength is 11)
		{
			value.V128 = AesArm.Encrypt(value.V128, keys.K9);
			value.V128 ^= keys.K10;
			return value;
		}

		if (_keyLength >= 13)
		{
			EncryptPart(ref value.V128, keys.K9);
			EncryptPart(ref value.V128, keys.K10);
		}

		if (_keyLength is 13)
		{
			value.V128 = AesArm.Encrypt(value.V128, keys.K11);
			value.V128 ^= keys.K12;
			return value;
		}

		EncryptPart(ref value.V128, keys.K11);
		EncryptPart(ref value.V128, keys.K12);

		value.V128 = AesArm.Encrypt(value.V128, keys.K13);
		value.V128 ^= keys.K14;

		return value;
	}

	public VectorBuffer16 Decrypt(scoped in VectorBuffer16 source)
	{
		VectorBuffer16 value = source;

		ref readonly AesKeys keys = ref _reverseRoundKeys;

		DecryptPart(ref value.V128, keys.K0);
		DecryptPart(ref value.V128, keys.K1);
		DecryptPart(ref value.V128, keys.K2);
		DecryptPart(ref value.V128, keys.K3);
		DecryptPart(ref value.V128, keys.K4);
		DecryptPart(ref value.V128, keys.K5);
		DecryptPart(ref value.V128, keys.K6);
		DecryptPart(ref value.V128, keys.K7);
		DecryptPart(ref value.V128, keys.K8);

		if (_keyLength is 11)
		{
			value.V128 = AesArm.Decrypt(value.V128, keys.K9);
			value.V128 ^= keys.K10;
			return value;
		}

		if (_keyLength >= 13)
		{
			DecryptPart(ref value.V128, keys.K9);
			DecryptPart(ref value.V128, keys.K10);
		}

		if (_keyLength is 13)
		{
			value.V128 = AesArm.Decrypt(value.V128, keys.K11);
			value.V128 ^= keys.K12;
			return value;
		}

		DecryptPart(ref value.V128, keys.K11);
		DecryptPart(ref value.V128, keys.K12);
		value.V128 = AesArm.Decrypt(value.V128, keys.K13);
		value.V128 ^= keys.K14;

		return value;
	}
}
