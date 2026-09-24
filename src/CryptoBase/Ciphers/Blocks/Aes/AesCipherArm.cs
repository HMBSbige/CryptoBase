using System.Diagnostics.CodeAnalysis;
using AesArm = System.Runtime.Intrinsics.Arm.Aes;

namespace CryptoBase.Ciphers.Blocks.Aes;

internal struct AesCipherArm : IDisposable, IAesVectorCore, IAesSubWord
{
	public static bool IsSupported => AesArm.IsSupported;

	internal int RoundKeyCount { get; }

	private AesKeys _roundKeys;
	private AesKeys _reverseRoundKeys;

	[UnscopedRef]
	internal readonly ref readonly AesKeys RoundKeys
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		get => ref _roundKeys;
	}

	public void Dispose()
	{
		_roundKeys.ZeroMemory();
		_reverseRoundKeys.ZeroMemory();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private AesCipherArm(ReadOnlySpan<byte> key)
	{
		Span<uint> keys = MemoryMarshal.CreateSpan(ref Unsafe.As<AesKeys, uint>(ref _roundKeys), 60);
		RoundKeyCount = AesKeySchedule.Expand<AesCipherArm>(key, keys) + 1;

		InverseExpandedKey
		(
			MemoryMarshal.CreateReadOnlySpan(ref Unsafe.As<AesKeys, Vector128<byte>>(ref _roundKeys), RoundKeyCount),
			MemoryMarshal.CreateSpan(ref Unsafe.As<AesKeys, Vector128<byte>>(ref _reverseRoundKeys), RoundKeyCount)
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
	static uint IAesSubWord.SubWord(uint x)
	{
		return AesArm.Encrypt(Vector128.Create(x).AsByte(), Vector128<byte>.Zero).AsUInt32().ToScalar();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static AesCipherArm Create(ReadOnlySpan<byte> key)
	{
		return new AesCipherArm(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly Vector128<byte> Encrypt(Vector128<byte> source)
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

		if (RoundKeyCount is 11)
		{
			value = AesArm.Encrypt(value, keys.K9);
			value ^= keys.K10;
			return value;
		}

		ProcessBlocks(ref value, keys.K9);
		ProcessBlocks(ref value, keys.K10);

		if (RoundKeyCount is 13)
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
	public readonly Vector128<byte> Decrypt(Vector128<byte> source)
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

		if (RoundKeyCount is 11)
		{
			value = AesArm.Decrypt(value, keys.K9);
			value ^= keys.K10;
			return value;
		}

		ProcessBlocks(ref value, keys.K9);
		ProcessBlocks(ref value, keys.K10);

		if (RoundKeyCount is 13)
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
	public readonly void Encrypt2(ref Vector128<byte> v0, ref Vector128<byte> v1)
	{
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

		if (RoundKeyCount is 11)
		{
			ProcessLastBlocks(ref v0, ref v1, keys.K9, keys.K10);
			return;
		}

		ProcessBlocks(ref v0, ref v1, keys.K9);
		ProcessBlocks(ref v0, ref v1, keys.K10);

		if (RoundKeyCount is 13)
		{
			ProcessLastBlocks(ref v0, ref v1, keys.K11, keys.K12);
			return;
		}

		ProcessBlocks(ref v0, ref v1, keys.K11);
		ProcessBlocks(ref v0, ref v1, keys.K12);

		ProcessLastBlocks(ref v0, ref v1, keys.K13, keys.K14);

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
	public readonly void Decrypt2(ref Vector128<byte> v0, ref Vector128<byte> v1)
	{
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

		if (RoundKeyCount is 11)
		{
			ProcessLastBlocks(ref v0, ref v1, keys.K9, keys.K10);
			return;
		}

		ProcessBlocks(ref v0, ref v1, keys.K9);
		ProcessBlocks(ref v0, ref v1, keys.K10);

		if (RoundKeyCount is 13)
		{
			ProcessLastBlocks(ref v0, ref v1, keys.K11, keys.K12);
			return;
		}

		ProcessBlocks(ref v0, ref v1, keys.K11);
		ProcessBlocks(ref v0, ref v1, keys.K12);
		ProcessLastBlocks(ref v0, ref v1, keys.K13, keys.K14);

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
	public readonly void Encrypt4(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3)
	{
		ref readonly AesKeys keys = ref _roundKeys;

		EncryptRound4(ref v0, ref v1, ref v2, ref v3, keys.K0);
		EncryptRound4(ref v0, ref v1, ref v2, ref v3, keys.K1);
		EncryptRound4(ref v0, ref v1, ref v2, ref v3, keys.K2);
		EncryptRound4(ref v0, ref v1, ref v2, ref v3, keys.K3);
		EncryptRound4(ref v0, ref v1, ref v2, ref v3, keys.K4);
		EncryptRound4(ref v0, ref v1, ref v2, ref v3, keys.K5);
		EncryptRound4(ref v0, ref v1, ref v2, ref v3, keys.K6);
		EncryptRound4(ref v0, ref v1, ref v2, ref v3, keys.K7);
		EncryptRound4(ref v0, ref v1, ref v2, ref v3, keys.K8);
		EncryptFinalRounds4(ref v0, ref v1, ref v2, ref v3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal readonly void EncryptFinalRounds4(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3)
	{
		ref readonly AesKeys keys = ref _roundKeys;

		if (RoundKeyCount is 11)
		{
			EncryptLastRound4(ref v0, ref v1, ref v2, ref v3, keys.K9, keys.K10);
			return;
		}

		EncryptRound4(ref v0, ref v1, ref v2, ref v3, keys.K9);
		EncryptRound4(ref v0, ref v1, ref v2, ref v3, keys.K10);

		if (RoundKeyCount is 13)
		{
			EncryptLastRound4(ref v0, ref v1, ref v2, ref v3, keys.K11, keys.K12);
			return;
		}

		EncryptRound4(ref v0, ref v1, ref v2, ref v3, keys.K11);
		EncryptRound4(ref v0, ref v1, ref v2, ref v3, keys.K12);
		EncryptLastRound4(ref v0, ref v1, ref v2, ref v3, keys.K13, keys.K14);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void EncryptLastRound4(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, Vector128<byte> key, Vector128<byte> lastKey)
	{
		v0 = AesArm.Encrypt(v0, key) ^ lastKey;
		v1 = AesArm.Encrypt(v1, key) ^ lastKey;
		v2 = AesArm.Encrypt(v2, key) ^ lastKey;
		v3 = AesArm.Encrypt(v3, key) ^ lastKey;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void EncryptRound4(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, Vector128<byte> key)
	{
		v0 = AesArm.MixColumns(AesArm.Encrypt(v0, key));
		v1 = AesArm.MixColumns(AesArm.Encrypt(v1, key));
		v2 = AesArm.MixColumns(AesArm.Encrypt(v2, key));
		v3 = AesArm.MixColumns(AesArm.Encrypt(v3, key));
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly void Decrypt4(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3)
	{
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

		if (RoundKeyCount is 11)
		{
			ProcessLastBlocks(ref v0, ref v1, ref v2, ref v3, keys.K9, keys.K10);
			return;
		}

		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K9);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K10);

		if (RoundKeyCount is 13)
		{
			ProcessLastBlocks(ref v0, ref v1, ref v2, ref v3, keys.K11, keys.K12);
			return;
		}

		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K11);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, keys.K12);
		ProcessLastBlocks(ref v0, ref v1, ref v2, ref v3, keys.K13, keys.K14);

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
	public readonly void Encrypt8(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7)
	{
		ref readonly AesKeys keys = ref _roundKeys;

		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K0);
		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K1);
		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K2);
		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K3);
		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K4);
		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K5);
		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K6);
		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K7);
		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K8);
		EncryptFinalRounds8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal readonly void EncryptFinalRounds8(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7)
	{
		ref readonly AesKeys keys = ref _roundKeys;

		if (RoundKeyCount is 11)
		{
			EncryptLastRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K9, keys.K10);
			return;
		}

		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K9);
		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K10);

		if (RoundKeyCount is 13)
		{
			EncryptLastRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K11, keys.K12);
			return;
		}

		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K11);
		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K12);
		EncryptLastRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K13, keys.K14);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void EncryptRound8(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7, Vector128<byte> key)
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
	internal static void EncryptLastRound8(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7, Vector128<byte> key, Vector128<byte> lastKey)
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

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly void Decrypt8(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7)
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

		if (RoundKeyCount is 11)
		{
			ProcessLastBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K9, keys.K10);
			return;
		}

		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K9);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, keys.K10);

		if (RoundKeyCount is 13)
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
}
