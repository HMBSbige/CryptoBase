using System.Diagnostics.CodeAnalysis;
using AesX86 = System.Runtime.Intrinsics.X86.Aes;

namespace CryptoBase.Ciphers.Blocks.Aes;

internal struct AesCipherX86 : IDisposable, IAesVectorCore
{
	public static bool IsSupported => AesX86.IsSupported;

	internal int RoundKeyCount { get; private set; }

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
	internal void Initialize(ReadOnlySpan<byte> key)
	{
		RoundKeyCount = Ssse3.IsSupported
			? ExpandKey<EncryptLastSubWord>(key, ref _roundKeys, ref _reverseRoundKeys)
			: ExpandKey<KeygenAssistSubWord>(key, ref _roundKeys, ref _reverseRoundKeys);
	}

	private interface IAesNiSubWord
	{
		static abstract Vector128<byte> SubRotWord3(Vector128<byte> value, [ConstantExpected] byte rcon);

		static abstract Vector128<byte> SubRotWord1(Vector128<byte> value, [ConstantExpected] byte rcon);

		static abstract Vector128<byte> SubWord3(Vector128<byte> value);
	}

	private readonly struct EncryptLastSubWord : IAesNiSubWord
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector128<byte> SubRotWord3(Vector128<byte> value, [ConstantExpected] byte rcon)
		{
			Vector128<byte> t = Ssse3.Shuffle(value, Vector128.Create(0x0C0F0E0Du).AsByte());
			return AesX86.EncryptLast(t, Vector128.Create((uint)rcon).AsByte());
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector128<byte> SubRotWord1(Vector128<byte> value, [ConstantExpected] byte rcon)
		{
			Vector128<byte> t = Ssse3.Shuffle(value, Vector128.Create(0x04070605u).AsByte());
			return AesX86.EncryptLast(t, Vector128.Create((uint)rcon).AsByte());
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector128<byte> SubWord3(Vector128<byte> value)
		{
			Vector128<byte> t = Sse2.Shuffle(value.AsUInt32(), 0b11_11_11_11).AsByte();
			return AesX86.EncryptLast(t, Vector128<byte>.Zero);
		}
	}

	private readonly struct KeygenAssistSubWord : IAesNiSubWord
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector128<byte> SubRotWord3(Vector128<byte> value, [ConstantExpected] byte rcon)
		{
			Vector128<byte> t = AesX86.KeygenAssist(value, rcon);
			return Sse2.Shuffle(t.AsUInt32(), 0b11_11_11_11).AsByte();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector128<byte> SubRotWord1(Vector128<byte> value, [ConstantExpected] byte rcon)
		{
			Vector128<byte> t = AesX86.KeygenAssist(value, rcon);
			return Sse2.Shuffle(t.AsUInt32(), 0b01_01_01_01).AsByte();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static Vector128<byte> SubWord3(Vector128<byte> value)
		{
			Vector128<byte> t = AesX86.KeygenAssist(value, AesKeySchedule.Rcon0);
			return Sse2.Shuffle(t.AsUInt32(), 0b10_10_10_10).AsByte();
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static int ExpandKey<T>(ReadOnlySpan<byte> key, ref AesKeys roundKeys, ref AesKeys inverseKeys) where T : struct, IAesNiSubWord
	{
		switch (key.Length)
		{
			case 16:
			{
				ExpandKey128<T>(key, ref roundKeys, ref inverseKeys);
				return 11;
			}
			case 24:
			{
				ExpandKey192<T>(key, ref roundKeys, ref inverseKeys);
				return 13;
			}
			case 32:
			{
				ExpandKey256<T>(key, ref roundKeys, ref inverseKeys);
				return 15;
			}
			default:
			{
				return ThrowHelper.ThrowArgumentOutOfRangeException<int>(nameof(key), "Key length must be 16/24/32 bytes");
			}
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> PrefixXor(Vector128<byte> value)
	{
		value ^= Sse2.ShiftLeftLogical128BitLane(value, 4);
		value ^= Sse2.ShiftLeftLogical128BitLane(value, 8);
		return value;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void StoreRoundKey(Vector128<byte> key, out Vector128<byte> roundKey, out Vector128<byte> inverseKey)
	{
		roundKey = key;
		inverseKey = AesX86.InverseMixColumns(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ExpandKey128<T>(ReadOnlySpan<byte> key, ref AesKeys roundKeys, ref AesKeys inverseKeys) where T : struct, IAesNiSubWord
	{
		Vector128<byte> k = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(key));
		roundKeys.K0 = inverseKeys.K10 = k;

		Round(ref k, AesKeySchedule.Rcon1, out roundKeys.K1, out inverseKeys.K9);
		Round(ref k, AesKeySchedule.Rcon2, out roundKeys.K2, out inverseKeys.K8);
		Round(ref k, AesKeySchedule.Rcon3, out roundKeys.K3, out inverseKeys.K7);
		Round(ref k, AesKeySchedule.Rcon4, out roundKeys.K4, out inverseKeys.K6);
		Round(ref k, AesKeySchedule.Rcon5, out roundKeys.K5, out inverseKeys.K5);
		Round(ref k, AesKeySchedule.Rcon6, out roundKeys.K6, out inverseKeys.K4);
		Round(ref k, AesKeySchedule.Rcon7, out roundKeys.K7, out inverseKeys.K3);
		Round(ref k, AesKeySchedule.Rcon8, out roundKeys.K8, out inverseKeys.K2);
		Round(ref k, AesKeySchedule.Rcon9, out roundKeys.K9, out inverseKeys.K1);
		roundKeys.K10 = inverseKeys.K0 = Next(k, AesKeySchedule.Rcon10);

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static Vector128<byte> Next(Vector128<byte> k, [ConstantExpected] byte rcon)
		{
			Vector128<byte> t = T.SubRotWord3(k, rcon);
			return PrefixXor(k) ^ t;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void Round(ref Vector128<byte> k, [ConstantExpected] byte rcon, out Vector128<byte> roundKey, out Vector128<byte> inverseKey)
		{
			k = Next(k, rcon);
			StoreRoundKey(k, out roundKey, out inverseKey);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ExpandKey192<T>(ReadOnlySpan<byte> key, ref AesKeys roundKeys, ref AesKeys inverseKeys) where T : struct, IAesNiSubWord
	{
		ref byte keyRef = ref MemoryMarshal.GetReference(key);
		Vector128<byte> a = Vector128.LoadUnsafe(ref keyRef);
		Vector128<byte> c = Vector128.CreateScalar(Unsafe.ReadUnaligned<ulong>(ref Unsafe.Add(ref keyRef, 16))).AsByte();
		roundKeys.K0 = inverseKeys.K12 = a;

		Round(ref a, ref c, AesKeySchedule.Rcon1, out roundKeys.K1, out inverseKeys.K11, out roundKeys.K2, out inverseKeys.K10);
		Next(ref a, ref c, AesKeySchedule.Rcon2);
		StoreRoundKey(a, out roundKeys.K3, out inverseKeys.K9);
		Round(ref a, ref c, AesKeySchedule.Rcon3, out roundKeys.K4, out inverseKeys.K8, out roundKeys.K5, out inverseKeys.K7);
		Next(ref a, ref c, AesKeySchedule.Rcon4);
		StoreRoundKey(a, out roundKeys.K6, out inverseKeys.K6);
		Round(ref a, ref c, AesKeySchedule.Rcon5, out roundKeys.K7, out inverseKeys.K5, out roundKeys.K8, out inverseKeys.K4);
		Next(ref a, ref c, AesKeySchedule.Rcon6);
		StoreRoundKey(a, out roundKeys.K9, out inverseKeys.K3);
		Round(ref a, ref c, AesKeySchedule.Rcon7, out roundKeys.K10, out inverseKeys.K2, out roundKeys.K11, out inverseKeys.K1);
		Next(ref a, ref c, AesKeySchedule.Rcon8);
		roundKeys.K12 = inverseKeys.K0 = a;

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void Next(ref Vector128<byte> a, ref Vector128<byte> c, [ConstantExpected] byte rcon)
		{
			Vector128<byte> t = T.SubRotWord1(c, rcon);
			a = PrefixXor(a) ^ t;
			c ^= Sse2.ShiftLeftLogical128BitLane(c, 4);
			c ^= Sse2.Shuffle(a.AsUInt32(), 0b11_11_11_11).AsByte();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void Round
		(
			ref Vector128<byte> a, ref Vector128<byte> c, [ConstantExpected] byte rcon,
			out Vector128<byte> roundKey0, out Vector128<byte> inverseKey0,
			out Vector128<byte> roundKey1, out Vector128<byte> inverseKey1
		)
		{
			Vector128<byte> previous = c;
			Next(ref a, ref c, rcon);
			StoreRoundKey(Sse2.Shuffle(previous.AsDouble(), a.AsDouble(), 0b0_0).AsByte(), out roundKey0, out inverseKey0);
			StoreRoundKey(Sse2.Shuffle(a.AsDouble(), c.AsDouble(), 0b0_1).AsByte(), out roundKey1, out inverseKey1);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ExpandKey256<T>(ReadOnlySpan<byte> key, ref AesKeys roundKeys, ref AesKeys inverseKeys) where T : struct, IAesNiSubWord
	{
		ref byte keyRef = ref MemoryMarshal.GetReference(key);
		Vector128<byte> a = Vector128.LoadUnsafe(ref keyRef);
		Vector128<byte> b = Vector128.LoadUnsafe(ref keyRef, 16);
		roundKeys.K0 = inverseKeys.K14 = a;
		StoreRoundKey(b, out roundKeys.K1, out inverseKeys.K13);

		Round(ref a, ref b, AesKeySchedule.Rcon1, out roundKeys.K2, out inverseKeys.K12, out roundKeys.K3, out inverseKeys.K11);
		Round(ref a, ref b, AesKeySchedule.Rcon2, out roundKeys.K4, out inverseKeys.K10, out roundKeys.K5, out inverseKeys.K9);
		Round(ref a, ref b, AesKeySchedule.Rcon3, out roundKeys.K6, out inverseKeys.K8, out roundKeys.K7, out inverseKeys.K7);
		Round(ref a, ref b, AesKeySchedule.Rcon4, out roundKeys.K8, out inverseKeys.K6, out roundKeys.K9, out inverseKeys.K5);
		Round(ref a, ref b, AesKeySchedule.Rcon5, out roundKeys.K10, out inverseKeys.K4, out roundKeys.K11, out inverseKeys.K3);
		Round(ref a, ref b, AesKeySchedule.Rcon6, out roundKeys.K12, out inverseKeys.K2, out roundKeys.K13, out inverseKeys.K1);

		Vector128<byte> t = T.SubRotWord3(b, AesKeySchedule.Rcon7);
		roundKeys.K14 = inverseKeys.K0 = PrefixXor(a) ^ t;

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void Round
		(
			ref Vector128<byte> a, ref Vector128<byte> b, [ConstantExpected] byte rcon,
			out Vector128<byte> roundKey0, out Vector128<byte> inverseKey0,
			out Vector128<byte> roundKey1, out Vector128<byte> inverseKey1
		)
		{
			Vector128<byte> t = T.SubRotWord3(b, rcon);
			a = PrefixXor(a) ^ t;
			StoreRoundKey(a, out roundKey0, out inverseKey0);

			t = T.SubWord3(a);
			b = PrefixXor(b) ^ t;
			StoreRoundKey(b, out roundKey1, out inverseKey1);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly Vector128<byte> Encrypt(Vector128<byte> source)
	{
		Vector128<byte> r = source;

		r ^= _roundKeys.K0;
		r = AesX86.Encrypt(r, _roundKeys.K1);
		r = AesX86.Encrypt(r, _roundKeys.K2);
		r = AesX86.Encrypt(r, _roundKeys.K3);
		r = AesX86.Encrypt(r, _roundKeys.K4);
		r = AesX86.Encrypt(r, _roundKeys.K5);
		r = AesX86.Encrypt(r, _roundKeys.K6);
		r = AesX86.Encrypt(r, _roundKeys.K7);
		r = AesX86.Encrypt(r, _roundKeys.K8);
		r = AesX86.Encrypt(r, _roundKeys.K9);

		if (RoundKeyCount is 11)
		{
			r = AesX86.EncryptLast(r, _roundKeys.K10);
			return r;
		}

		r = AesX86.Encrypt(r, _roundKeys.K10);
		r = AesX86.Encrypt(r, _roundKeys.K11);

		if (RoundKeyCount is 13)
		{
			r = AesX86.EncryptLast(r, _roundKeys.K12);
			return r;
		}

		r = AesX86.Encrypt(r, _roundKeys.K12);
		r = AesX86.Encrypt(r, _roundKeys.K13);
		r = AesX86.EncryptLast(r, _roundKeys.K14);

		return r;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly Vector128<byte> Decrypt(Vector128<byte> source)
	{
		Vector128<byte> r = source;

		r ^= _reverseRoundKeys.K0;
		r = AesX86.Decrypt(r, _reverseRoundKeys.K1);
		r = AesX86.Decrypt(r, _reverseRoundKeys.K2);
		r = AesX86.Decrypt(r, _reverseRoundKeys.K3);
		r = AesX86.Decrypt(r, _reverseRoundKeys.K4);
		r = AesX86.Decrypt(r, _reverseRoundKeys.K5);
		r = AesX86.Decrypt(r, _reverseRoundKeys.K6);
		r = AesX86.Decrypt(r, _reverseRoundKeys.K7);
		r = AesX86.Decrypt(r, _reverseRoundKeys.K8);
		r = AesX86.Decrypt(r, _reverseRoundKeys.K9);

		if (RoundKeyCount is 11)
		{
			r = AesX86.DecryptLast(r, _reverseRoundKeys.K10);
			return r;
		}

		r = AesX86.Decrypt(r, _reverseRoundKeys.K10);
		r = AesX86.Decrypt(r, _reverseRoundKeys.K11);

		if (RoundKeyCount is 13)
		{
			r = AesX86.DecryptLast(r, _reverseRoundKeys.K12);
			return r;
		}

		r = AesX86.Decrypt(r, _reverseRoundKeys.K12);
		r = AesX86.Decrypt(r, _reverseRoundKeys.K13);
		r = AesX86.DecryptLast(r, _reverseRoundKeys.K14);

		return r;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly void Encrypt2(ref Vector128<byte> v0, ref Vector128<byte> v1)
	{
		v0 ^= _roundKeys.K0;
		v1 ^= _roundKeys.K0;

		ProcessBlocks(ref v0, ref v1, _roundKeys.K1);
		ProcessBlocks(ref v0, ref v1, _roundKeys.K2);
		ProcessBlocks(ref v0, ref v1, _roundKeys.K3);
		ProcessBlocks(ref v0, ref v1, _roundKeys.K4);
		ProcessBlocks(ref v0, ref v1, _roundKeys.K5);
		ProcessBlocks(ref v0, ref v1, _roundKeys.K6);
		ProcessBlocks(ref v0, ref v1, _roundKeys.K7);
		ProcessBlocks(ref v0, ref v1, _roundKeys.K8);
		ProcessBlocks(ref v0, ref v1, _roundKeys.K9);

		if (RoundKeyCount is 11)
		{
			ProcessLastBlocks(ref v0, ref v1, _roundKeys.K10);
			return;
		}

		ProcessBlocks(ref v0, ref v1, _roundKeys.K10);
		ProcessBlocks(ref v0, ref v1, _roundKeys.K11);

		if (RoundKeyCount is 13)
		{
			ProcessLastBlocks(ref v0, ref v1, _roundKeys.K12);
			return;
		}

		ProcessBlocks(ref v0, ref v1, _roundKeys.K12);
		ProcessBlocks(ref v0, ref v1, _roundKeys.K13);
		ProcessLastBlocks(ref v0, ref v1, _roundKeys.K14);

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessBlocks(ref Vector128<byte> v0, ref Vector128<byte> v1, Vector128<byte> key)
		{
			v0 = AesX86.Encrypt(v0, key);
			v1 = AesX86.Encrypt(v1, key);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessLastBlocks(ref Vector128<byte> v0, ref Vector128<byte> v1, Vector128<byte> key)
		{
			v0 = AesX86.EncryptLast(v0, key);
			v1 = AesX86.EncryptLast(v1, key);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly void Decrypt2(ref Vector128<byte> v0, ref Vector128<byte> v1)
	{
		v0 ^= _reverseRoundKeys.K0;
		v1 ^= _reverseRoundKeys.K0;

		ProcessBlocks(ref v0, ref v1, _reverseRoundKeys.K1);
		ProcessBlocks(ref v0, ref v1, _reverseRoundKeys.K2);
		ProcessBlocks(ref v0, ref v1, _reverseRoundKeys.K3);
		ProcessBlocks(ref v0, ref v1, _reverseRoundKeys.K4);
		ProcessBlocks(ref v0, ref v1, _reverseRoundKeys.K5);
		ProcessBlocks(ref v0, ref v1, _reverseRoundKeys.K6);
		ProcessBlocks(ref v0, ref v1, _reverseRoundKeys.K7);
		ProcessBlocks(ref v0, ref v1, _reverseRoundKeys.K8);
		ProcessBlocks(ref v0, ref v1, _reverseRoundKeys.K9);

		if (RoundKeyCount is 11)
		{
			ProcessLastBlocks(ref v0, ref v1, _reverseRoundKeys.K10);
			return;
		}

		ProcessBlocks(ref v0, ref v1, _reverseRoundKeys.K10);
		ProcessBlocks(ref v0, ref v1, _reverseRoundKeys.K11);

		if (RoundKeyCount is 13)
		{
			ProcessLastBlocks(ref v0, ref v1, _reverseRoundKeys.K12);
			return;
		}

		ProcessBlocks(ref v0, ref v1, _reverseRoundKeys.K12);
		ProcessBlocks(ref v0, ref v1, _reverseRoundKeys.K13);
		ProcessLastBlocks(ref v0, ref v1, _reverseRoundKeys.K14);

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessBlocks(ref Vector128<byte> v0, ref Vector128<byte> v1, Vector128<byte> key)
		{
			v0 = AesX86.Decrypt(v0, key);
			v1 = AesX86.Decrypt(v1, key);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessLastBlocks(ref Vector128<byte> v0, ref Vector128<byte> v1, Vector128<byte> key)
		{
			v0 = AesX86.DecryptLast(v0, key);
			v1 = AesX86.DecryptLast(v1, key);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly void Encrypt4(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3)
	{
		v0 ^= _roundKeys.K0;
		v1 ^= _roundKeys.K0;
		v2 ^= _roundKeys.K0;
		v3 ^= _roundKeys.K0;

		EncryptRound4(ref v0, ref v1, ref v2, ref v3, _roundKeys.K1);
		EncryptRound4(ref v0, ref v1, ref v2, ref v3, _roundKeys.K2);
		EncryptRound4(ref v0, ref v1, ref v2, ref v3, _roundKeys.K3);
		EncryptRound4(ref v0, ref v1, ref v2, ref v3, _roundKeys.K4);
		EncryptRound4(ref v0, ref v1, ref v2, ref v3, _roundKeys.K5);
		EncryptRound4(ref v0, ref v1, ref v2, ref v3, _roundKeys.K6);
		EncryptRound4(ref v0, ref v1, ref v2, ref v3, _roundKeys.K7);
		EncryptRound4(ref v0, ref v1, ref v2, ref v3, _roundKeys.K8);
		EncryptRound4(ref v0, ref v1, ref v2, ref v3, _roundKeys.K9);

		EncryptFinalRounds4(ref v0, ref v1, ref v2, ref v3);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal readonly void EncryptFinalRounds4(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3)
	{
		if (RoundKeyCount is 11)
		{
			EncryptLastRound4(ref v0, ref v1, ref v2, ref v3, _roundKeys.K10);
			return;
		}

		EncryptRound4(ref v0, ref v1, ref v2, ref v3, _roundKeys.K10);
		EncryptRound4(ref v0, ref v1, ref v2, ref v3, _roundKeys.K11);

		if (RoundKeyCount is 13)
		{
			EncryptLastRound4(ref v0, ref v1, ref v2, ref v3, _roundKeys.K12);
			return;
		}

		EncryptRound4(ref v0, ref v1, ref v2, ref v3, _roundKeys.K12);
		EncryptRound4(ref v0, ref v1, ref v2, ref v3, _roundKeys.K13);
		EncryptLastRound4(ref v0, ref v1, ref v2, ref v3, _roundKeys.K14);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void EncryptRound4(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, Vector128<byte> key)
	{
		v0 = AesX86.Encrypt(v0, key);
		v1 = AesX86.Encrypt(v1, key);
		v2 = AesX86.Encrypt(v2, key);
		v3 = AesX86.Encrypt(v3, key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void EncryptLastRound4(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, Vector128<byte> key)
	{
		v0 = AesX86.EncryptLast(v0, key);
		v1 = AesX86.EncryptLast(v1, key);
		v2 = AesX86.EncryptLast(v2, key);
		v3 = AesX86.EncryptLast(v3, key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly void Decrypt4(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3)
	{
		v0 ^= _reverseRoundKeys.K0;
		v1 ^= _reverseRoundKeys.K0;
		v2 ^= _reverseRoundKeys.K0;
		v3 ^= _reverseRoundKeys.K0;

		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, _reverseRoundKeys.K1);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, _reverseRoundKeys.K2);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, _reverseRoundKeys.K3);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, _reverseRoundKeys.K4);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, _reverseRoundKeys.K5);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, _reverseRoundKeys.K6);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, _reverseRoundKeys.K7);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, _reverseRoundKeys.K8);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, _reverseRoundKeys.K9);

		if (RoundKeyCount is 11)
		{
			ProcessLastBlocks(ref v0, ref v1, ref v2, ref v3, _reverseRoundKeys.K10);
			return;
		}

		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, _reverseRoundKeys.K10);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, _reverseRoundKeys.K11);

		if (RoundKeyCount is 13)
		{
			ProcessLastBlocks(ref v0, ref v1, ref v2, ref v3, _reverseRoundKeys.K12);
			return;
		}

		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, _reverseRoundKeys.K12);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, _reverseRoundKeys.K13);
		ProcessLastBlocks(ref v0, ref v1, ref v2, ref v3, _reverseRoundKeys.K14);

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessBlocks(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, Vector128<byte> key)
		{
			v0 = AesX86.Decrypt(v0, key);
			v1 = AesX86.Decrypt(v1, key);
			v2 = AesX86.Decrypt(v2, key);
			v3 = AesX86.Decrypt(v3, key);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessLastBlocks(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, Vector128<byte> key)
		{
			v0 = AesX86.DecryptLast(v0, key);
			v1 = AesX86.DecryptLast(v1, key);
			v2 = AesX86.DecryptLast(v2, key);
			v3 = AesX86.DecryptLast(v3, key);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly void Encrypt8(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7)
	{
		v0 ^= _roundKeys.K0;
		v1 ^= _roundKeys.K0;
		v2 ^= _roundKeys.K0;
		v3 ^= _roundKeys.K0;
		v4 ^= _roundKeys.K0;
		v5 ^= _roundKeys.K0;
		v6 ^= _roundKeys.K0;
		v7 ^= _roundKeys.K0;

		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _roundKeys.K1);
		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _roundKeys.K2);
		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _roundKeys.K3);
		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _roundKeys.K4);
		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _roundKeys.K5);
		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _roundKeys.K6);
		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _roundKeys.K7);
		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _roundKeys.K8);
		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _roundKeys.K9);

		EncryptFinalRounds8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal readonly void EncryptFinalRounds8(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7)
	{
		if (RoundKeyCount is 11)
		{
			EncryptLastRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _roundKeys.K10);
			return;
		}

		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _roundKeys.K10);
		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _roundKeys.K11);

		if (RoundKeyCount is 13)
		{
			EncryptLastRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _roundKeys.K12);
			return;
		}

		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _roundKeys.K12);
		EncryptRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _roundKeys.K13);
		EncryptLastRound8(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _roundKeys.K14);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal static void EncryptRound8(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7, Vector128<byte> key)
	{
		v0 = AesX86.Encrypt(v0, key);
		v1 = AesX86.Encrypt(v1, key);
		v2 = AesX86.Encrypt(v2, key);
		v3 = AesX86.Encrypt(v3, key);
		v4 = AesX86.Encrypt(v4, key);
		v5 = AesX86.Encrypt(v5, key);
		v6 = AesX86.Encrypt(v6, key);
		v7 = AesX86.Encrypt(v7, key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void EncryptLastRound8(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7, Vector128<byte> key)
	{
		v0 = AesX86.EncryptLast(v0, key);
		v1 = AesX86.EncryptLast(v1, key);
		v2 = AesX86.EncryptLast(v2, key);
		v3 = AesX86.EncryptLast(v3, key);
		v4 = AesX86.EncryptLast(v4, key);
		v5 = AesX86.EncryptLast(v5, key);
		v6 = AesX86.EncryptLast(v6, key);
		v7 = AesX86.EncryptLast(v7, key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public readonly void Decrypt8(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7)
	{
		v0 ^= _reverseRoundKeys.K0;
		v1 ^= _reverseRoundKeys.K0;
		v2 ^= _reverseRoundKeys.K0;
		v3 ^= _reverseRoundKeys.K0;
		v4 ^= _reverseRoundKeys.K0;
		v5 ^= _reverseRoundKeys.K0;
		v6 ^= _reverseRoundKeys.K0;
		v7 ^= _reverseRoundKeys.K0;

		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _reverseRoundKeys.K1);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _reverseRoundKeys.K2);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _reverseRoundKeys.K3);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _reverseRoundKeys.K4);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _reverseRoundKeys.K5);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _reverseRoundKeys.K6);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _reverseRoundKeys.K7);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _reverseRoundKeys.K8);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _reverseRoundKeys.K9);

		if (RoundKeyCount is 11)
		{
			ProcessLastBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _reverseRoundKeys.K10);
			return;
		}

		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _reverseRoundKeys.K10);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _reverseRoundKeys.K11);

		if (RoundKeyCount is 13)
		{
			ProcessLastBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _reverseRoundKeys.K12);
			return;
		}

		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _reverseRoundKeys.K12);
		ProcessBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _reverseRoundKeys.K13);
		ProcessLastBlocks(ref v0, ref v1, ref v2, ref v3, ref v4, ref v5, ref v6, ref v7, _reverseRoundKeys.K14);

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessBlocks(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7, Vector128<byte> key)
		{
			v0 = AesX86.Decrypt(v0, key);
			v1 = AesX86.Decrypt(v1, key);
			v2 = AesX86.Decrypt(v2, key);
			v3 = AesX86.Decrypt(v3, key);
			v4 = AesX86.Decrypt(v4, key);
			v5 = AesX86.Decrypt(v5, key);
			v6 = AesX86.Decrypt(v6, key);
			v7 = AesX86.Decrypt(v7, key);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void ProcessLastBlocks(ref Vector128<byte> v0, ref Vector128<byte> v1, ref Vector128<byte> v2, ref Vector128<byte> v3, ref Vector128<byte> v4, ref Vector128<byte> v5, ref Vector128<byte> v6, ref Vector128<byte> v7, Vector128<byte> key)
		{
			v0 = AesX86.DecryptLast(v0, key);
			v1 = AesX86.DecryptLast(v1, key);
			v2 = AesX86.DecryptLast(v2, key);
			v3 = AesX86.DecryptLast(v3, key);
			v4 = AesX86.DecryptLast(v4, key);
			v5 = AesX86.DecryptLast(v5, key);
			v6 = AesX86.DecryptLast(v6, key);
			v7 = AesX86.DecryptLast(v7, key);
		}
	}
}
