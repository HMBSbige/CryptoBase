using AesArm = System.Runtime.Intrinsics.Arm.Aes;

namespace CryptoBase.Ciphers.Blocks.Aes;

internal struct AesCipherArm
{
	public static bool IsSupported => AesArm.IsSupported;

	private readonly int _keyLength;

	private AesKeys _roundKeys;
	private AesKeys _reverseRoundKeys;

	public void Dispose()
	{
		_roundKeys.ZeroMemory();
		_reverseRoundKeys.ZeroMemory();
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
	private readonly Vector128<byte> Encrypt(Vector128<byte> source)
	{
		Vector128<byte> value = source;

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
			value = AesArm.Encrypt(value, keys.K9);
			value ^= keys.K10;
			return value;
		}

		ProcessBlocks(ref value, keys.K9);
		ProcessBlocks(ref value, keys.K10);

		if (_keyLength is 13)
		{
			value = AesArm.Encrypt(value, keys.K11);
			value ^= keys.K12;
			return value;
		}

		ProcessBlocks(ref value, keys.K11);
		ProcessBlocks(ref value, keys.K12);

		value = AesArm.Encrypt(value, keys.K13);
		value ^= keys.K14;

		return value;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessBlocks(ref Vector128<byte> state, Vector128<byte> key)
		{
			state = AesArm.MixColumns(AesArm.Encrypt(state, key));
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private readonly Vector128<byte> Decrypt(Vector128<byte> source)
	{
		Vector128<byte> value = source;

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
			value = AesArm.Decrypt(value, keys.K9);
			value ^= keys.K10;
			return value;
		}

		ProcessBlocks(ref value, keys.K9);
		ProcessBlocks(ref value, keys.K10);

		if (_keyLength is 13)
		{
			value = AesArm.Decrypt(value, keys.K11);
			value ^= keys.K12;
			return value;
		}

		ProcessBlocks(ref value, keys.K11);
		ProcessBlocks(ref value, keys.K12);
		value = AesArm.Decrypt(value, keys.K13);
		value ^= keys.K14;

		return value;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessBlocks(ref Vector128<byte> state, Vector128<byte> key)
		{
			state = AesArm.InverseMixColumns(AesArm.Decrypt(state, key));
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private readonly void Encrypt2(ref byte source, ref byte destination)
	{
		Vector128<byte> v0 = Vector128.LoadUnsafe(ref source, 0);
		Vector128<byte> v1 = Vector128.LoadUnsafe(ref source, 16);

		ref readonly AesKeys keys = ref _roundKeys;

		ProcessBlocks(ref v0, ref v1, keys.K0);
		ProcessBlocks(ref v0, ref v1, keys.K1);
		ProcessBlocks(ref v0, ref v1, keys.K2);
		ProcessBlocks(ref v0, ref v1, keys.K3);
		ProcessBlocks(ref v0, ref v1, keys.K4);
		ProcessBlocks(ref v0, ref v1, keys.K5);
		ProcessBlocks(ref v0, ref v1, keys.K6);
		ProcessBlocks(ref v0, ref v1, keys.K7);
		ProcessBlocks(ref v0, ref v1, keys.K8);

		if (_keyLength is 11)
		{
			ProcessLastBlocks(ref v0, ref v1, keys.K9, keys.K10);
			v0.StoreUnsafe(ref destination, 0);
			v1.StoreUnsafe(ref destination, 16);
			return;
		}

		ProcessBlocks(ref v0, ref v1, keys.K9);
		ProcessBlocks(ref v0, ref v1, keys.K10);

		if (_keyLength is 13)
		{
			ProcessLastBlocks(ref v0, ref v1, keys.K11, keys.K12);
			v0.StoreUnsafe(ref destination, 0);
			v1.StoreUnsafe(ref destination, 16);
			return;
		}

		ProcessBlocks(ref v0, ref v1, keys.K11);
		ProcessBlocks(ref v0, ref v1, keys.K12);

		ProcessLastBlocks(ref v0, ref v1, keys.K13, keys.K14);

		v0.StoreUnsafe(ref destination, 0);
		v1.StoreUnsafe(ref destination, 16);
		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessBlocks(ref Vector128<byte> v0, ref Vector128<byte> v1, Vector128<byte> key)
		{
			v0 = AesArm.MixColumns(AesArm.Encrypt(v0, key));
			v1 = AesArm.MixColumns(AesArm.Encrypt(v1, key));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessLastBlocks(ref Vector128<byte> v0, ref Vector128<byte> v1, Vector128<byte> key, Vector128<byte> lastKey)
		{
			v0 = AesArm.Encrypt(v0, key);
			v1 = AesArm.Encrypt(v1, key);

			v0 ^= lastKey;
			v1 ^= lastKey;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private readonly void Decrypt2(ref byte source, ref byte destination)
	{
		Vector128<byte> v0 = Vector128.LoadUnsafe(ref source, 0);
		Vector128<byte> v1 = Vector128.LoadUnsafe(ref source, 16);

		ref readonly AesKeys keys = ref _reverseRoundKeys;

		ProcessBlocks(ref v0, ref v1, keys.K0);
		ProcessBlocks(ref v0, ref v1, keys.K1);
		ProcessBlocks(ref v0, ref v1, keys.K2);
		ProcessBlocks(ref v0, ref v1, keys.K3);
		ProcessBlocks(ref v0, ref v1, keys.K4);
		ProcessBlocks(ref v0, ref v1, keys.K5);
		ProcessBlocks(ref v0, ref v1, keys.K6);
		ProcessBlocks(ref v0, ref v1, keys.K7);
		ProcessBlocks(ref v0, ref v1, keys.K8);

		if (_keyLength is 11)
		{
			ProcessLastBlocks(ref v0, ref v1, keys.K9, keys.K10);
			v0.StoreUnsafe(ref destination, 0);
			v1.StoreUnsafe(ref destination, 16);
			return;
		}

		ProcessBlocks(ref v0, ref v1, keys.K9);
		ProcessBlocks(ref v0, ref v1, keys.K10);

		if (_keyLength is 13)
		{
			ProcessLastBlocks(ref v0, ref v1, keys.K11, keys.K12);
			v0.StoreUnsafe(ref destination, 0);
			v1.StoreUnsafe(ref destination, 16);
			return;
		}

		ProcessBlocks(ref v0, ref v1, keys.K11);
		ProcessBlocks(ref v0, ref v1, keys.K12);
		ProcessLastBlocks(ref v0, ref v1, keys.K13, keys.K14);

		v0.StoreUnsafe(ref destination, 0);
		v1.StoreUnsafe(ref destination, 16);
		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessBlocks(ref Vector128<byte> v0, ref Vector128<byte> v1, Vector128<byte> key)
		{
			v0 = AesArm.InverseMixColumns(AesArm.Decrypt(v0, key));
			v1 = AesArm.InverseMixColumns(AesArm.Decrypt(v1, key));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessLastBlocks(ref Vector128<byte> v0, ref Vector128<byte> v1, Vector128<byte> key, Vector128<byte> lastKey)
		{
			v0 = AesArm.Decrypt(v0, key);
			v1 = AesArm.Decrypt(v1, key);

			v0 ^= lastKey;
			v1 ^= lastKey;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private readonly void Encrypt4(ref byte source, ref byte destination)
	{
		Vector128<byte> v0 = Vector128.LoadUnsafe(ref source, 0);
		Vector128<byte> v1 = Vector128.LoadUnsafe(ref source, 16);
		Vector128<byte> v2 = Vector128.LoadUnsafe(ref source, 32);
		Vector128<byte> v3 = Vector128.LoadUnsafe(ref source, 48);

		ref readonly AesKeys keys = ref _roundKeys;

		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K0);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K1);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K2);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K3);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K4);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K5);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K6);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K7);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K8);

		if (_keyLength is 11)
		{
			ProcessLastBlocks(ref v0, ref v1, ref v2, ref v3, keys.K9, keys.K10);
			v0.StoreUnsafe(ref destination, 0);
			v1.StoreUnsafe(ref destination, 16);
			v2.StoreUnsafe(ref destination, 32);
			v3.StoreUnsafe(ref destination, 48);
			return;
		}

		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K9);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K10);

		if (_keyLength is 13)
		{
			ProcessLastBlocks(ref v0, ref v1, ref v2, ref v3, keys.K11, keys.K12);
			v0.StoreUnsafe(ref destination, 0);
			v1.StoreUnsafe(ref destination, 16);
			v2.StoreUnsafe(ref destination, 32);
			v3.StoreUnsafe(ref destination, 48);
			return;
		}

		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K11);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K12);

		ProcessLastBlocks(ref v0, ref v1, ref v2, ref v3, keys.K13, keys.K14);

		v0.StoreUnsafe(ref destination, 0);
		v1.StoreUnsafe(ref destination, 16);
		v2.StoreUnsafe(ref destination, 32);
		v3.StoreUnsafe(ref destination, 48);
		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessBlocks(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, Vector128<byte> key)
		{
			v0 = AesArm.MixColumns(AesArm.Encrypt(v0, key));
			v1 = AesArm.MixColumns(AesArm.Encrypt(v1, key));
			v2 = AesArm.MixColumns(AesArm.Encrypt(v2, key));
			v3 = AesArm.MixColumns(AesArm.Encrypt(v3, key));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessLastBlocks(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, Vector128<byte> key, Vector128<byte> lastKey)
		{
			v0 = AesArm.Encrypt(v0, key);
			v1 = AesArm.Encrypt(v1, key);
			v2 = AesArm.Encrypt(v2, key);
			v3 = AesArm.Encrypt(v3, key);

			v0 ^= lastKey;
			v1 ^= lastKey;
			v2 ^= lastKey;
			v3 ^= lastKey;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private readonly void Decrypt4(ref byte source, ref byte destination)
	{
		Vector128<byte> v0 = Vector128.LoadUnsafe(ref source, 0);
		Vector128<byte> v1 = Vector128.LoadUnsafe(ref source, 16);
		Vector128<byte> v2 = Vector128.LoadUnsafe(ref source, 32);
		Vector128<byte> v3 = Vector128.LoadUnsafe(ref source, 48);

		ref readonly AesKeys keys = ref _reverseRoundKeys;

		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K0);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K1);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K2);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K3);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K4);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K5);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K6);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K7);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K8);

		if (_keyLength is 11)
		{
			ProcessLastBlocks(ref v0, ref v1, ref v2, ref v3, keys.K9, keys.K10);
			v0.StoreUnsafe(ref destination, 0);
			v1.StoreUnsafe(ref destination, 16);
			v2.StoreUnsafe(ref destination, 32);
			v3.StoreUnsafe(ref destination, 48);
			return;
		}

		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K9);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K10);

		if (_keyLength is 13)
		{
			ProcessLastBlocks(ref v0, ref v1, ref v2, ref v3, keys.K11, keys.K12);
			v0.StoreUnsafe(ref destination, 0);
			v1.StoreUnsafe(ref destination, 16);
			v2.StoreUnsafe(ref destination, 32);
			v3.StoreUnsafe(ref destination, 48);
			return;
		}

		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K11);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K12);
		ProcessLastBlocks(ref v0, ref v1, ref v2, ref v3, keys.K13, keys.K14);

		v0.StoreUnsafe(ref destination, 0);
		v1.StoreUnsafe(ref destination, 16);
		v2.StoreUnsafe(ref destination, 32);
		v3.StoreUnsafe(ref destination, 48);
		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessBlocks(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, Vector128<byte> key)
		{
			v0 = AesArm.InverseMixColumns(AesArm.Decrypt(v0, key));
			v1 = AesArm.InverseMixColumns(AesArm.Decrypt(v1, key));
			v2 = AesArm.InverseMixColumns(AesArm.Decrypt(v2, key));
			v3 = AesArm.InverseMixColumns(AesArm.Decrypt(v3, key));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessLastBlocks(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, Vector128<byte> key, Vector128<byte> lastKey)
		{
			v0 = AesArm.Decrypt(v0, key);
			v1 = AesArm.Decrypt(v1, key);
			v2 = AesArm.Decrypt(v2, key);
			v3 = AesArm.Decrypt(v3, key);

			v0 ^= lastKey;
			v1 ^= lastKey;
			v2 ^= lastKey;
			v3 ^= lastKey;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private readonly void Encrypt8(ref byte source, ref byte destination)
	{
		Vector128<byte> v0 = Vector128.LoadUnsafe(ref source, 0);
		Vector128<byte> v1 = Vector128.LoadUnsafe(ref source, 16);
		Vector128<byte> v2 = Vector128.LoadUnsafe(ref source, 32);
		Vector128<byte> v3 = Vector128.LoadUnsafe(ref source, 48);
		Vector128<byte> v4 = Vector128.LoadUnsafe(ref source, 64);
		Vector128<byte> v5 = Vector128.LoadUnsafe(ref source, 80);
		Vector128<byte> v6 = Vector128.LoadUnsafe(ref source, 96);
		Vector128<byte> v7 = Vector128.LoadUnsafe(ref source, 112);
		Encrypt8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
		v0.StoreUnsafe(ref destination, 0);
		v1.StoreUnsafe(ref destination, 16);
		v2.StoreUnsafe(ref destination, 32);
		v3.StoreUnsafe(ref destination, 48);
		v4.StoreUnsafe(ref destination, 64);
		v5.StoreUnsafe(ref destination, 80);
		v6.StoreUnsafe(ref destination, 96);
		v7.StoreUnsafe(ref destination, 112);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private readonly void Encrypt8(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7)
	{
		ref readonly AesKeys keys = ref _roundKeys;

		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K0);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K1);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K2);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K3);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K4);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K5);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K6);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K7);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K8);

		if (_keyLength is 11)
		{
			ProcessLastBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K9, keys.K10);
			return;
		}

		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K9);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K10);

		if (_keyLength is 13)
		{
			ProcessLastBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K11, keys.K12);
			return;
		}

		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K11);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K12);

		ProcessLastBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K13, keys.K14);

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessBlocks(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7, Vector128<byte> key)
		{
			v0 = AesArm.MixColumns(AesArm.Encrypt(v0, key));
			v1 = AesArm.MixColumns(AesArm.Encrypt(v1, key));
			v2 = AesArm.MixColumns(AesArm.Encrypt(v2, key));
			v3 = AesArm.MixColumns(AesArm.Encrypt(v3, key));
			v4 = AesArm.MixColumns(AesArm.Encrypt(v4, key));
			v5 = AesArm.MixColumns(AesArm.Encrypt(v5, key));
			v6 = AesArm.MixColumns(AesArm.Encrypt(v6, key));
			v7 = AesArm.MixColumns(AesArm.Encrypt(v7, key));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessLastBlocks(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7, Vector128<byte> key, Vector128<byte> lastKey)
		{
			v0 = AesArm.Encrypt(v0, key);
			v1 = AesArm.Encrypt(v1, key);
			v2 = AesArm.Encrypt(v2, key);
			v3 = AesArm.Encrypt(v3, key);
			v4 = AesArm.Encrypt(v4, key);
			v5 = AesArm.Encrypt(v5, key);
			v6 = AesArm.Encrypt(v6, key);
			v7 = AesArm.Encrypt(v7, key);

			v0 ^= lastKey;
			v1 ^= lastKey;
			v2 ^= lastKey;
			v3 ^= lastKey;
			v4 ^= lastKey;
			v5 ^= lastKey;
			v6 ^= lastKey;
			v7 ^= lastKey;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private readonly void Decrypt8(ref byte source, ref byte destination)
	{
		Vector128<byte> v0 = Vector128.LoadUnsafe(ref source, 0);
		Vector128<byte> v1 = Vector128.LoadUnsafe(ref source, 16);
		Vector128<byte> v2 = Vector128.LoadUnsafe(ref source, 32);
		Vector128<byte> v3 = Vector128.LoadUnsafe(ref source, 48);
		Vector128<byte> v4 = Vector128.LoadUnsafe(ref source, 64);
		Vector128<byte> v5 = Vector128.LoadUnsafe(ref source, 80);
		Vector128<byte> v6 = Vector128.LoadUnsafe(ref source, 96);
		Vector128<byte> v7 = Vector128.LoadUnsafe(ref source, 112);
		Decrypt8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
		v0.StoreUnsafe(ref destination, 0);
		v1.StoreUnsafe(ref destination, 16);
		v2.StoreUnsafe(ref destination, 32);
		v3.StoreUnsafe(ref destination, 48);
		v4.StoreUnsafe(ref destination, 64);
		v5.StoreUnsafe(ref destination, 80);
		v6.StoreUnsafe(ref destination, 96);
		v7.StoreUnsafe(ref destination, 112);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private readonly void Decrypt8(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7)
	{
		ref readonly AesKeys keys = ref _reverseRoundKeys;

		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K0);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K1);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K2);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K3);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K4);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K5);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K6);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K7);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K8);

		if (_keyLength is 11)
		{
			ProcessLastBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K9, keys.K10);
			return;
		}

		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K9);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K10);

		if (_keyLength is 13)
		{
			ProcessLastBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K11, keys.K12);
			return;
		}

		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K11);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K12);
		ProcessLastBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K13, keys.K14);

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessBlocks(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7, Vector128<byte> key)
		{
			v0 = AesArm.InverseMixColumns(AesArm.Decrypt(v0, key));
			v1 = AesArm.InverseMixColumns(AesArm.Decrypt(v1, key));
			v2 = AesArm.InverseMixColumns(AesArm.Decrypt(v2, key));
			v3 = AesArm.InverseMixColumns(AesArm.Decrypt(v3, key));
			v4 = AesArm.InverseMixColumns(AesArm.Decrypt(v4, key));
			v5 = AesArm.InverseMixColumns(AesArm.Decrypt(v5, key));
			v6 = AesArm.InverseMixColumns(AesArm.Decrypt(v6, key));
			v7 = AesArm.InverseMixColumns(AesArm.Decrypt(v7, key));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessLastBlocks(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7, Vector128<byte> key, Vector128<byte> lastKey)
		{
			v0 = AesArm.Decrypt(v0, key);
			v1 = AesArm.Decrypt(v1, key);
			v2 = AesArm.Decrypt(v2, key);
			v3 = AesArm.Decrypt(v3, key);
			v4 = AesArm.Decrypt(v4, key);
			v5 = AesArm.Decrypt(v5, key);
			v6 = AesArm.Decrypt(v6, key);
			v7 = AesArm.Decrypt(v7, key);

			v0 ^= lastKey;
			v1 ^= lastKey;
			v2 ^= lastKey;
			v3 ^= lastKey;
			v4 ^= lastKey;
			v5 ^= lastKey;
			v6 ^= lastKey;
			v7 ^= lastKey;
		}
	}

	public readonly void EncryptBlocks(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ref byte src = ref source.GetReference();
		ref byte dst = ref destination.GetReference();
		int offset = 0;

		while (source.Length - offset >= 128)
		{
			Encrypt8(ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset));
			offset += 128;
		}

		while (source.Length - offset >= 64)
		{
			Encrypt4(ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset));
			offset += 64;
		}

		while (source.Length - offset >= 32)
		{
			Encrypt2(ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset));
			offset += 32;
		}

		if (offset < source.Length)
		{
			Encrypt(Vector128.LoadUnsafe(ref src, (nuint)offset)).StoreUnsafe(ref dst, (nuint)offset);
		}
	}

	public readonly void DecryptBlocks(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ref byte src = ref source.GetReference();
		ref byte dst = ref destination.GetReference();
		int offset = 0;

		while (source.Length - offset >= 128)
		{
			Decrypt8(ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset));
			offset += 128;
		}

		while (source.Length - offset >= 64)
		{
			Decrypt4(ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset));
			offset += 64;
		}

		while (source.Length - offset >= 32)
		{
			Decrypt2(ref Unsafe.Add(ref src, offset), ref Unsafe.Add(ref dst, offset));
			offset += 32;
		}

		if (offset < source.Length)
		{
			Decrypt(Vector128.LoadUnsafe(ref src, (nuint)offset)).StoreUnsafe(ref dst, (nuint)offset);
		}
	}

	// Fuses the mode's XOR with AES to avoid intermediate ciphertext/keystream stores.
	public readonly void TransformWithMask(ReadOnlySpan<byte> source, ReadOnlySpan<byte> mask, Span<byte> destination, bool decrypt, bool xorInput)
	{
		ref byte src = ref source.GetReference();
		ref byte xor = ref mask.GetReference();
		ref byte dst = ref destination.GetReference();
		int offset = 0;

		for (; offset <= source.Length - 128; offset += 128)
		{
			Vector128<byte> v0 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 0));
			Vector128<byte> v1 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 16));
			Vector128<byte> v2 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 32));
			Vector128<byte> v3 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 48));
			Vector128<byte> v4 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 64));
			Vector128<byte> v5 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 80));
			Vector128<byte> v6 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 96));
			Vector128<byte> v7 = Vector128.LoadUnsafe(ref src, (nuint)(offset + 112));

			if (xorInput)
			{
				v0 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 0));
				v1 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 16));
				v2 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 32));
				v3 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 48));
				v4 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 64));
				v5 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 80));
				v6 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 96));
				v7 ^= Vector128.LoadUnsafe(ref xor, (nuint)(offset + 112));
			}

			if (decrypt)
			{
				Decrypt8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
			}
			else
			{
				Encrypt8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
			}

			(v0 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 0))).StoreUnsafe(ref dst, (nuint)(offset + 0));
			(v1 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 16))).StoreUnsafe(ref dst, (nuint)(offset + 16));
			(v2 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 32))).StoreUnsafe(ref dst, (nuint)(offset + 32));
			(v3 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 48))).StoreUnsafe(ref dst, (nuint)(offset + 48));
			(v4 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 64))).StoreUnsafe(ref dst, (nuint)(offset + 64));
			(v5 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 80))).StoreUnsafe(ref dst, (nuint)(offset + 80));
			(v6 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 96))).StoreUnsafe(ref dst, (nuint)(offset + 96));
			(v7 ^ Vector128.LoadUnsafe(ref xor, (nuint)(offset + 112))).StoreUnsafe(ref dst, (nuint)(offset + 112));
		}

		for (; offset < source.Length; offset += 16)
		{
			Vector128<byte> value = Vector128.LoadUnsafe(ref src, (nuint)offset);
			Vector128<byte> blockMask = Vector128.LoadUnsafe(ref xor, (nuint)offset);

			if (xorInput)
			{
				value ^= blockMask;
			}

			value = decrypt ? Decrypt(value) : Encrypt(value);
			(value ^ blockMask).StoreUnsafe(ref dst, (nuint)offset);
		}
	}
}
