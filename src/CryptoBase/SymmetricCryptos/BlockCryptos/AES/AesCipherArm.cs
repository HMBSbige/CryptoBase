namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

internal readonly struct AesCipherArm : IBlock16Cipher<AesCipherArm>
{
	public string Name => @"AES";

	public static bool IsSupported => AesArm.IsSupported;

	public static BlockCipherHardwareAcceleration HardwareAcceleration => BlockCipherHardwareAcceleration.Block1 | BlockCipherHardwareAcceleration.Block2 | BlockCipherHardwareAcceleration.Block4 | BlockCipherHardwareAcceleration.Block8;

	private readonly int _keyLength;

	private readonly AesKeys _roundKeys;
	private readonly AesKeys _reverseRoundKeys;

	public void Dispose()
	{
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private AesCipherArm(in ReadOnlySpan<byte> key)
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
				t = SubWord(t).RotateRight(8) ^ AesCipher.Rcon[i / nk];
			}
			else if (nk > 6 && i % nk is 4)
			{
				t = SubWord(t);
			}

			keys[i] = keys[i - nk] ^ t;
		}

		InverseExpandedKey
		(
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
	public static AesCipherArm Create(in ReadOnlySpan<byte> key)
	{
		return new AesCipherArm(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer16 Encrypt(scoped in VectorBuffer16 source)
	{
		VectorBuffer16 value = source;

		ref readonly AesKeys keys = ref _roundKeys;

		ProcessBlocks(ref value.V128, keys.K0);
		ProcessBlocks(ref value.V128, keys.K1);
		ProcessBlocks(ref value.V128, keys.K2);
		ProcessBlocks(ref value.V128, keys.K3);
		ProcessBlocks(ref value.V128, keys.K4);
		ProcessBlocks(ref value.V128, keys.K5);
		ProcessBlocks(ref value.V128, keys.K6);
		ProcessBlocks(ref value.V128, keys.K7);
		ProcessBlocks(ref value.V128, keys.K8);

		if (_keyLength is 11)
		{
			value.V128 = AesArm.Encrypt(value.V128, keys.K9);
			value.V128 ^= keys.K10;
			return value;
		}

		ProcessBlocks(ref value.V128, keys.K9);
		ProcessBlocks(ref value.V128, keys.K10);

		if (_keyLength is 13)
		{
			value.V128 = AesArm.Encrypt(value.V128, keys.K11);
			value.V128 ^= keys.K12;
			return value;
		}

		ProcessBlocks(ref value.V128, keys.K11);
		ProcessBlocks(ref value.V128, keys.K12);

		value.V128 = AesArm.Encrypt(value.V128, keys.K13);
		value.V128 ^= keys.K14;

		return value;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessBlocks(ref Vector128<byte> state, Vector128<byte> key)
		{
			state = AesArm.MixColumns(AesArm.Encrypt(state, key));
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer16 Decrypt(scoped in VectorBuffer16 source)
	{
		VectorBuffer16 value = source;

		ref readonly AesKeys keys = ref _reverseRoundKeys;

		ProcessBlocks(ref value.V128, keys.K0);
		ProcessBlocks(ref value.V128, keys.K1);
		ProcessBlocks(ref value.V128, keys.K2);
		ProcessBlocks(ref value.V128, keys.K3);
		ProcessBlocks(ref value.V128, keys.K4);
		ProcessBlocks(ref value.V128, keys.K5);
		ProcessBlocks(ref value.V128, keys.K6);
		ProcessBlocks(ref value.V128, keys.K7);
		ProcessBlocks(ref value.V128, keys.K8);

		if (_keyLength is 11)
		{
			value.V128 = AesArm.Decrypt(value.V128, keys.K9);
			value.V128 ^= keys.K10;
			return value;
		}

		ProcessBlocks(ref value.V128, keys.K9);
		ProcessBlocks(ref value.V128, keys.K10);

		if (_keyLength is 13)
		{
			value.V128 = AesArm.Decrypt(value.V128, keys.K11);
			value.V128 ^= keys.K12;
			return value;
		}

		ProcessBlocks(ref value.V128, keys.K11);
		ProcessBlocks(ref value.V128, keys.K12);
		value.V128 = AesArm.Decrypt(value.V128, keys.K13);
		value.V128 ^= keys.K14;

		return value;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessBlocks(ref Vector128<byte> state, Vector128<byte> key)
		{
			state = AesArm.InverseMixColumns(AesArm.Decrypt(state, key));
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer32 Encrypt(scoped in VectorBuffer32 source)
	{
		VectorBuffer32 value = source;

		ref readonly AesKeys keys = ref _roundKeys;

		ProcessBlocks(ref value, keys.K0);
		ProcessBlocks(ref value, keys.K1);
		ProcessBlocks(ref value, keys.K2);
		ProcessBlocks(ref value, keys.K3);
		ProcessBlocks(ref value, keys.K4);
		ProcessBlocks(ref value, keys.K5);
		ProcessBlocks(ref value, keys.K6);
		ProcessBlocks(ref value, keys.K7);
		ProcessBlocks(ref value, keys.K8);

		if (_keyLength is 11)
		{
			ProcessLastBlocks(ref value, keys.K9, keys.K10);
			return value;
		}

		ProcessBlocks(ref value, keys.K9);
		ProcessBlocks(ref value, keys.K10);

		if (_keyLength is 13)
		{
			ProcessLastBlocks(ref value, keys.K11, keys.K12);
			return value;
		}

		ProcessBlocks(ref value, keys.K11);
		ProcessBlocks(ref value, keys.K12);

		ProcessLastBlocks(ref value, keys.K13, keys.K14);

		return value;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessBlocks(ref VectorBuffer32 state, Vector128<byte> key)
		{
			state.V128_0 = AesArm.MixColumns(AesArm.Encrypt(state.V128_0, key));
			state.V128_1 = AesArm.MixColumns(AesArm.Encrypt(state.V128_1, key));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessLastBlocks(ref VectorBuffer32 state, Vector128<byte> key, Vector128<byte> lastKey)
		{
			state.V128_0 = AesArm.Encrypt(state.V128_0, key);
			state.V128_1 = AesArm.Encrypt(state.V128_1, key);

			state.V128_0 ^= lastKey;
			state.V128_1 ^= lastKey;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer32 Decrypt(scoped in VectorBuffer32 source)
	{
		VectorBuffer32 value = source;
		ref readonly AesKeys keys = ref _reverseRoundKeys;

		ProcessBlocks(ref value, keys.K0);
		ProcessBlocks(ref value, keys.K1);
		ProcessBlocks(ref value, keys.K2);
		ProcessBlocks(ref value, keys.K3);
		ProcessBlocks(ref value, keys.K4);
		ProcessBlocks(ref value, keys.K5);
		ProcessBlocks(ref value, keys.K6);
		ProcessBlocks(ref value, keys.K7);
		ProcessBlocks(ref value, keys.K8);

		if (_keyLength is 11)
		{
			ProcessLastBlocks(ref value, keys.K9, keys.K10);
			return value;
		}

		ProcessBlocks(ref value, keys.K9);
		ProcessBlocks(ref value, keys.K10);

		if (_keyLength is 13)
		{
			ProcessLastBlocks(ref value, keys.K11, keys.K12);
			return value;
		}

		ProcessBlocks(ref value, keys.K11);
		ProcessBlocks(ref value, keys.K12);
		ProcessLastBlocks(ref value, keys.K13, keys.K14);

		return value;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessBlocks(ref VectorBuffer32 state, Vector128<byte> key)
		{
			state.V128_0 = AesArm.InverseMixColumns(AesArm.Decrypt(state.V128_0, key));
			state.V128_1 = AesArm.InverseMixColumns(AesArm.Decrypt(state.V128_1, key));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessLastBlocks(ref VectorBuffer32 state, Vector128<byte> key, Vector128<byte> lastKey)
		{
			state.V128_0 = AesArm.Decrypt(state.V128_0, key);
			state.V128_1 = AesArm.Decrypt(state.V128_1, key);

			state.V128_0 ^= lastKey;
			state.V128_1 ^= lastKey;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer64 Encrypt(scoped in VectorBuffer64 source)
	{
		VectorBuffer64 value = source;

		ref readonly AesKeys keys = ref _roundKeys;

		ProcessBlocks(ref value, keys.K0);
		ProcessBlocks(ref value, keys.K1);
		ProcessBlocks(ref value, keys.K2);
		ProcessBlocks(ref value, keys.K3);
		ProcessBlocks(ref value, keys.K4);
		ProcessBlocks(ref value, keys.K5);
		ProcessBlocks(ref value, keys.K6);
		ProcessBlocks(ref value, keys.K7);
		ProcessBlocks(ref value, keys.K8);

		if (_keyLength is 11)
		{
			ProcessLastBlocks(ref value, keys.K9, keys.K10);
			return value;
		}

		ProcessBlocks(ref value, keys.K9);
		ProcessBlocks(ref value, keys.K10);

		if (_keyLength is 13)
		{
			ProcessLastBlocks(ref value, keys.K11, keys.K12);
			return value;
		}

		ProcessBlocks(ref value, keys.K11);
		ProcessBlocks(ref value, keys.K12);

		ProcessLastBlocks(ref value, keys.K13, keys.K14);

		return value;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessBlocks(ref VectorBuffer64 state, Vector128<byte> key)
		{
			state.V128_0 = AesArm.MixColumns(AesArm.Encrypt(state.V128_0, key));
			state.V128_1 = AesArm.MixColumns(AesArm.Encrypt(state.V128_1, key));
			state.V128_2 = AesArm.MixColumns(AesArm.Encrypt(state.V128_2, key));
			state.V128_3 = AesArm.MixColumns(AesArm.Encrypt(state.V128_3, key));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessLastBlocks(ref VectorBuffer64 state, Vector128<byte> key, Vector128<byte> lastKey)
		{
			state.V128_0 = AesArm.Encrypt(state.V128_0, key);
			state.V128_1 = AesArm.Encrypt(state.V128_1, key);
			state.V128_2 = AesArm.Encrypt(state.V128_2, key);
			state.V128_3 = AesArm.Encrypt(state.V128_3, key);

			state.V128_0 ^= lastKey;
			state.V128_1 ^= lastKey;
			state.V128_2 ^= lastKey;
			state.V128_3 ^= lastKey;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer64 Decrypt(scoped in VectorBuffer64 source)
	{
		VectorBuffer64 value = source;
		ref readonly AesKeys keys = ref _reverseRoundKeys;

		ProcessBlocks(ref value, keys.K0);
		ProcessBlocks(ref value, keys.K1);
		ProcessBlocks(ref value, keys.K2);
		ProcessBlocks(ref value, keys.K3);
		ProcessBlocks(ref value, keys.K4);
		ProcessBlocks(ref value, keys.K5);
		ProcessBlocks(ref value, keys.K6);
		ProcessBlocks(ref value, keys.K7);
		ProcessBlocks(ref value, keys.K8);

		if (_keyLength is 11)
		{
			ProcessLastBlocks(ref value, keys.K9, keys.K10);
			return value;
		}

		ProcessBlocks(ref value, keys.K9);
		ProcessBlocks(ref value, keys.K10);

		if (_keyLength is 13)
		{
			ProcessLastBlocks(ref value, keys.K11, keys.K12);
			return value;
		}

		ProcessBlocks(ref value, keys.K11);
		ProcessBlocks(ref value, keys.K12);
		ProcessLastBlocks(ref value, keys.K13, keys.K14);

		return value;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessBlocks(ref VectorBuffer64 state, Vector128<byte> key)
		{
			state.V128_0 = AesArm.InverseMixColumns(AesArm.Decrypt(state.V128_0, key));
			state.V128_1 = AesArm.InverseMixColumns(AesArm.Decrypt(state.V128_1, key));
			state.V128_2 = AesArm.InverseMixColumns(AesArm.Decrypt(state.V128_2, key));
			state.V128_3 = AesArm.InverseMixColumns(AesArm.Decrypt(state.V128_3, key));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessLastBlocks(ref VectorBuffer64 state, Vector128<byte> key, Vector128<byte> lastKey)
		{
			state.V128_0 = AesArm.Decrypt(state.V128_0, key);
			state.V128_1 = AesArm.Decrypt(state.V128_1, key);
			state.V128_2 = AesArm.Decrypt(state.V128_2, key);
			state.V128_3 = AesArm.Decrypt(state.V128_3, key);

			state.V128_0 ^= lastKey;
			state.V128_1 ^= lastKey;
			state.V128_2 ^= lastKey;
			state.V128_3 ^= lastKey;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer128 Encrypt(scoped in VectorBuffer128 source)
	{
		VectorBuffer128 value = source;

		ref readonly AesKeys keys = ref _roundKeys;

		ProcessBlocks(ref value, keys.K0);
		ProcessBlocks(ref value, keys.K1);
		ProcessBlocks(ref value, keys.K2);
		ProcessBlocks(ref value, keys.K3);
		ProcessBlocks(ref value, keys.K4);
		ProcessBlocks(ref value, keys.K5);
		ProcessBlocks(ref value, keys.K6);
		ProcessBlocks(ref value, keys.K7);
		ProcessBlocks(ref value, keys.K8);

		if (_keyLength is 11)
		{
			ProcessLastBlocks(ref value, keys.K9, keys.K10);
			return value;
		}

		ProcessBlocks(ref value, keys.K9);
		ProcessBlocks(ref value, keys.K10);

		if (_keyLength is 13)
		{
			ProcessLastBlocks(ref value, keys.K11, keys.K12);
			return value;
		}

		ProcessBlocks(ref value, keys.K11);
		ProcessBlocks(ref value, keys.K12);

		ProcessLastBlocks(ref value, keys.K13, keys.K14);

		return value;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessBlocks(ref VectorBuffer128 state, Vector128<byte> key)
		{
			state.V128_0 = AesArm.MixColumns(AesArm.Encrypt(state.V128_0, key));
			state.V128_1 = AesArm.MixColumns(AesArm.Encrypt(state.V128_1, key));
			state.V128_2 = AesArm.MixColumns(AesArm.Encrypt(state.V128_2, key));
			state.V128_3 = AesArm.MixColumns(AesArm.Encrypt(state.V128_3, key));
			state.V128_4 = AesArm.MixColumns(AesArm.Encrypt(state.V128_4, key));
			state.V128_5 = AesArm.MixColumns(AesArm.Encrypt(state.V128_5, key));
			state.V128_6 = AesArm.MixColumns(AesArm.Encrypt(state.V128_6, key));
			state.V128_7 = AesArm.MixColumns(AesArm.Encrypt(state.V128_7, key));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessLastBlocks(ref VectorBuffer128 state, Vector128<byte> key, Vector128<byte> lastKey)
		{
			state.V128_0 = AesArm.Encrypt(state.V128_0, key);
			state.V128_1 = AesArm.Encrypt(state.V128_1, key);
			state.V128_2 = AesArm.Encrypt(state.V128_2, key);
			state.V128_3 = AesArm.Encrypt(state.V128_3, key);
			state.V128_4 = AesArm.Encrypt(state.V128_4, key);
			state.V128_5 = AesArm.Encrypt(state.V128_5, key);
			state.V128_6 = AesArm.Encrypt(state.V128_6, key);
			state.V128_7 = AesArm.Encrypt(state.V128_7, key);

			state.V128_0 ^= lastKey;
			state.V128_1 ^= lastKey;
			state.V128_2 ^= lastKey;
			state.V128_3 ^= lastKey;
			state.V128_4 ^= lastKey;
			state.V128_5 ^= lastKey;
			state.V128_6 ^= lastKey;
			state.V128_7 ^= lastKey;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer128 Decrypt(scoped in VectorBuffer128 source)
	{
		VectorBuffer128 value = source;
		ref readonly AesKeys keys = ref _reverseRoundKeys;

		ProcessBlocks(ref value, keys.K0);
		ProcessBlocks(ref value, keys.K1);
		ProcessBlocks(ref value, keys.K2);
		ProcessBlocks(ref value, keys.K3);
		ProcessBlocks(ref value, keys.K4);
		ProcessBlocks(ref value, keys.K5);
		ProcessBlocks(ref value, keys.K6);
		ProcessBlocks(ref value, keys.K7);
		ProcessBlocks(ref value, keys.K8);

		if (_keyLength is 11)
		{
			ProcessLastBlocks(ref value, keys.K9, keys.K10);
			return value;
		}

		ProcessBlocks(ref value, keys.K9);
		ProcessBlocks(ref value, keys.K10);

		if (_keyLength is 13)
		{
			ProcessLastBlocks(ref value, keys.K11, keys.K12);
			return value;
		}

		ProcessBlocks(ref value, keys.K11);
		ProcessBlocks(ref value, keys.K12);
		ProcessLastBlocks(ref value, keys.K13, keys.K14);

		return value;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessBlocks(ref VectorBuffer128 state, Vector128<byte> key)
		{
			state.V128_0 = AesArm.InverseMixColumns(AesArm.Decrypt(state.V128_0, key));
			state.V128_1 = AesArm.InverseMixColumns(AesArm.Decrypt(state.V128_1, key));
			state.V128_2 = AesArm.InverseMixColumns(AesArm.Decrypt(state.V128_2, key));
			state.V128_3 = AesArm.InverseMixColumns(AesArm.Decrypt(state.V128_3, key));
			state.V128_4 = AesArm.InverseMixColumns(AesArm.Decrypt(state.V128_4, key));
			state.V128_5 = AesArm.InverseMixColumns(AesArm.Decrypt(state.V128_5, key));
			state.V128_6 = AesArm.InverseMixColumns(AesArm.Decrypt(state.V128_6, key));
			state.V128_7 = AesArm.InverseMixColumns(AesArm.Decrypt(state.V128_7, key));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessLastBlocks(ref VectorBuffer128 state, Vector128<byte> key, Vector128<byte> lastKey)
		{
			state.V128_0 = AesArm.Decrypt(state.V128_0, key);
			state.V128_1 = AesArm.Decrypt(state.V128_1, key);
			state.V128_2 = AesArm.Decrypt(state.V128_2, key);
			state.V128_3 = AesArm.Decrypt(state.V128_3, key);
			state.V128_4 = AesArm.Decrypt(state.V128_4, key);
			state.V128_5 = AesArm.Decrypt(state.V128_5, key);
			state.V128_6 = AesArm.Decrypt(state.V128_6, key);
			state.V128_7 = AesArm.Decrypt(state.V128_7, key);

			state.V128_0 ^= lastKey;
			state.V128_1 ^= lastKey;
			state.V128_2 ^= lastKey;
			state.V128_3 ^= lastKey;
			state.V128_4 ^= lastKey;
			state.V128_5 ^= lastKey;
			state.V128_6 ^= lastKey;
			state.V128_7 ^= lastKey;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer128 EncryptV256(scoped in VectorBuffer128 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer128 DecryptV256(scoped in VectorBuffer128 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer256 EncryptV256(scoped in VectorBuffer256 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer256 DecryptV256(scoped in VectorBuffer256 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer256 EncryptV512(scoped in VectorBuffer256 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer256 DecryptV512(scoped in VectorBuffer256 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer512 EncryptV512(scoped in VectorBuffer512 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer512 DecryptV512(scoped in VectorBuffer512 source)
	{
		ThrowHelper.ThrowNotSupported();
		return default;
	}
}
