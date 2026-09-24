using System.Diagnostics.CodeAnalysis;
using AesX86 = System.Runtime.Intrinsics.X86.Aes;

namespace CryptoBase.Ciphers.Blocks.Aes;

internal struct AesCipherX86 : IDisposable, IAesVectorCore
{
	public static bool IsSupported => AesX86.IsSupported && Sse2.IsSupported;

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
	private AesCipherX86(ReadOnlySpan<byte> key)
	{
		switch (key.Length)
		{
			case 16:
			{
				RoundKeyCount = 11;
				ExpandKey128(key, ref _roundKeys);
				InverseExpandedKey128(_roundKeys, ref _reverseRoundKeys);
				break;
			}
			case 24:
			{
				RoundKeyCount = 13;
				ExpandKey192(key, ref _roundKeys);
				InverseExpandedKey192(_roundKeys, ref _reverseRoundKeys);
				break;
			}
			case 32:
			{
				RoundKeyCount = 15;
				ExpandKey256(key, ref _roundKeys);
				InverseExpandedKey256(_roundKeys, ref _reverseRoundKeys);
				break;
			}
			default:
			{
				ThrowHelper.ThrowArgumentOutOfRangeException<int>(nameof(key), "Key length must be 16/24/32 bytes");
				break;
			}
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ExpandKey128(ReadOnlySpan<byte> key, ref AesKeys roundKeys)
	{
		roundKeys.K0 = Vector128.LoadUnsafe(ref key.GetReference());

		roundKeys.K1 = KeyRound(roundKeys.K0, AesKeySchedule.Rcon1);
		roundKeys.K2 = KeyRound(roundKeys.K1, AesKeySchedule.Rcon2);
		roundKeys.K3 = KeyRound(roundKeys.K2, AesKeySchedule.Rcon3);
		roundKeys.K4 = KeyRound(roundKeys.K3, AesKeySchedule.Rcon4);
		roundKeys.K5 = KeyRound(roundKeys.K4, AesKeySchedule.Rcon5);
		roundKeys.K6 = KeyRound(roundKeys.K5, AesKeySchedule.Rcon6);
		roundKeys.K7 = KeyRound(roundKeys.K6, AesKeySchedule.Rcon7);
		roundKeys.K8 = KeyRound(roundKeys.K7, AesKeySchedule.Rcon8);
		roundKeys.K9 = KeyRound(roundKeys.K8, AesKeySchedule.Rcon9);
		roundKeys.K10 = KeyRound(roundKeys.K9, AesKeySchedule.Rcon10);

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static Vector128<byte> KeyRound(Vector128<byte> key, [ConstantExpected] byte rcon)
		{
			Vector128<byte> t = AesX86.KeygenAssist(key, rcon);
			t = Sse2.Shuffle(t.AsUInt32(), 0b11_11_11_11).AsByte();

			key ^= Sse2.ShiftLeftLogical128BitLane(key, 4);
			key ^= Sse2.ShiftLeftLogical128BitLane(key, 8);

			return key ^ t;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ExpandKey192(ReadOnlySpan<byte> key, ref AesKeys roundKeys)
	{
		ref byte keyRef = ref key.GetReference();

		roundKeys.K12 = Vector128.LoadUnsafe(ref keyRef);// 0,15

		ref readonly ulong t = ref Unsafe.Add(ref keyRef, 16).As<ulong>();
		Vector128<byte> t1 = Vector128.CreateScalar(t).AsByte();// 16,23

		KeyRound(out roundKeys.K0, out roundKeys.K1, out roundKeys.K2, ref roundKeys.K12, ref t1, AesKeySchedule.Rcon1, AesKeySchedule.Rcon2);
		KeyRound(out roundKeys.K3, out roundKeys.K4, out roundKeys.K5, ref roundKeys.K12, ref t1, AesKeySchedule.Rcon3, AesKeySchedule.Rcon4);
		KeyRound(out roundKeys.K6, out roundKeys.K7, out roundKeys.K8, ref roundKeys.K12, ref t1, AesKeySchedule.Rcon5, AesKeySchedule.Rcon6);
		KeyRound(out roundKeys.K9, out roundKeys.K10, out roundKeys.K11, ref roundKeys.K12, ref t1, AesKeySchedule.Rcon7, AesKeySchedule.Rcon8);

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void KeyRound0(ref Vector128<byte> a, ref Vector128<byte> b, ref Vector128<byte> c)
		{
			Vector128<byte> t = Sse2.ShiftLeftLogical128BitLane(a, 4);
			b = Sse2.Shuffle(b.AsUInt32(), 0b01_01_01_01).AsByte();
			a ^= t;
			t = Sse2.ShiftLeftLogical128BitLane(t, 4);
			a ^= t;
			t = Sse2.ShiftLeftLogical128BitLane(t, 4);
			a ^= t;
			a ^= b;
			b = Sse2.Shuffle(a.AsUInt32(), 0b11_11_11_11).AsByte();
			t = Sse2.ShiftLeftLogical128BitLane(c, 4);
			c ^= t;
			c ^= b;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void KeyRound(
			out Vector128<byte> a, out Vector128<byte> b, out Vector128<byte> c,
			ref Vector128<byte> t0, ref Vector128<byte> t1,
			[ConstantExpected] byte rcon0, [ConstantExpected] byte rcon1)
		{
			a = t0;
			b = t1;
			Vector128<byte> t2 = AesX86.KeygenAssist(t1, rcon0);
			KeyRound0(ref t0, ref t2, ref t1);

			b = Sse2.Shuffle(b.AsDouble(), t0.AsDouble(), 0b0_0).AsByte();
			c = Sse2.Shuffle(t0.AsDouble(), t1.AsDouble(), 0b0_1).AsByte();
			t2 = AesX86.KeygenAssist(t1, rcon1);
			KeyRound0(ref t0, ref t2, ref t1);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ExpandKey256(ReadOnlySpan<byte> key, ref AesKeys roundKeys)
	{
		ref byte keyRef = ref key.GetReference();

		roundKeys.K0 = roundKeys.K14 = Vector128.LoadUnsafe(ref keyRef);// 0,15
		roundKeys.K13 = Vector128.LoadUnsafe(ref keyRef, 16);// 15,31

		KeyRound(out roundKeys.K1, out roundKeys.K2, ref roundKeys.K14, ref roundKeys.K13, AesKeySchedule.Rcon1);
		KeyRound(out roundKeys.K3, out roundKeys.K4, ref roundKeys.K14, ref roundKeys.K13, AesKeySchedule.Rcon2);
		KeyRound(out roundKeys.K5, out roundKeys.K6, ref roundKeys.K14, ref roundKeys.K13, AesKeySchedule.Rcon3);
		KeyRound(out roundKeys.K7, out roundKeys.K8, ref roundKeys.K14, ref roundKeys.K13, AesKeySchedule.Rcon4);
		KeyRound(out roundKeys.K9, out roundKeys.K10, ref roundKeys.K14, ref roundKeys.K13, AesKeySchedule.Rcon5);
		KeyRound(out roundKeys.K11, out roundKeys.K12, ref roundKeys.K14, ref roundKeys.K13, AesKeySchedule.Rcon6);

		Vector128<byte> t2 = AesX86.KeygenAssist(roundKeys.K13, AesKeySchedule.Rcon7);
		KeyRound1(ref roundKeys.K14, ref t2);

		return;

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void KeyRound1(ref Vector128<byte> a, ref Vector128<byte> b)
		{
			Vector128<byte> t = Sse2.ShiftLeftLogical128BitLane(a, 4);
			b = Sse2.Shuffle(b.AsUInt32(), 0b11_11_11_11).AsByte();
			a ^= t;
			t = Sse2.ShiftLeftLogical128BitLane(t, 4);
			a ^= t;
			t = Sse2.ShiftLeftLogical128BitLane(t, 4);
			a ^= t;
			a ^= b;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void KeyRound2(ref Vector128<byte> a, ref Vector128<byte> b)
		{
			Vector128<byte> t0 = AesX86.KeygenAssist(a, AesKeySchedule.Rcon0);
			Vector128<byte> t1 = Sse2.Shuffle(t0.AsUInt32(), 0b10_10_10_10).AsByte();

			t0 = Sse2.ShiftLeftLogical128BitLane(b, 4);
			b ^= t0;
			t0 = Sse2.ShiftLeftLogical128BitLane(t0, 4);
			b ^= t0;
			t0 = Sse2.ShiftLeftLogical128BitLane(t0, 4);
			b ^= t0;
			b ^= t1;
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		static void KeyRound(out Vector128<byte> a, out Vector128<byte> b, ref Vector128<byte> t0, ref Vector128<byte> t1, [ConstantExpected] byte rcon)
		{
			a = t1;
			Vector128<byte> t2 = AesX86.KeygenAssist(t1, rcon);
			KeyRound1(ref t0, ref t2);
			b = t0;
			KeyRound2(ref t0, ref t1);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseExpandedKey128(in AesKeys roundKeys, ref AesKeys keys)
	{
		keys.K0 = roundKeys.K10;
		keys.K1 = AesX86.InverseMixColumns(roundKeys.K9);
		keys.K2 = AesX86.InverseMixColumns(roundKeys.K8);
		keys.K3 = AesX86.InverseMixColumns(roundKeys.K7);
		keys.K4 = AesX86.InverseMixColumns(roundKeys.K6);
		keys.K5 = AesX86.InverseMixColumns(roundKeys.K5);
		keys.K6 = AesX86.InverseMixColumns(roundKeys.K4);
		keys.K7 = AesX86.InverseMixColumns(roundKeys.K3);
		keys.K8 = AesX86.InverseMixColumns(roundKeys.K2);
		keys.K9 = AesX86.InverseMixColumns(roundKeys.K1);
		keys.K10 = roundKeys.K0;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseExpandedKey192(in AesKeys roundKeys, ref AesKeys keys)
	{
		keys.K0 = roundKeys.K12;
		keys.K1 = AesX86.InverseMixColumns(roundKeys.K11);
		keys.K2 = AesX86.InverseMixColumns(roundKeys.K10);
		keys.K3 = AesX86.InverseMixColumns(roundKeys.K9);
		keys.K4 = AesX86.InverseMixColumns(roundKeys.K8);
		keys.K5 = AesX86.InverseMixColumns(roundKeys.K7);
		keys.K6 = AesX86.InverseMixColumns(roundKeys.K6);
		keys.K7 = AesX86.InverseMixColumns(roundKeys.K5);
		keys.K8 = AesX86.InverseMixColumns(roundKeys.K4);
		keys.K9 = AesX86.InverseMixColumns(roundKeys.K3);
		keys.K10 = AesX86.InverseMixColumns(roundKeys.K2);
		keys.K11 = AesX86.InverseMixColumns(roundKeys.K1);
		keys.K12 = roundKeys.K0;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void InverseExpandedKey256(in AesKeys roundKeys, ref AesKeys keys)
	{
		keys.K0 = roundKeys.K14;
		keys.K1 = AesX86.InverseMixColumns(roundKeys.K13);
		keys.K2 = AesX86.InverseMixColumns(roundKeys.K12);
		keys.K3 = AesX86.InverseMixColumns(roundKeys.K11);
		keys.K4 = AesX86.InverseMixColumns(roundKeys.K10);
		keys.K5 = AesX86.InverseMixColumns(roundKeys.K9);
		keys.K6 = AesX86.InverseMixColumns(roundKeys.K8);
		keys.K7 = AesX86.InverseMixColumns(roundKeys.K7);
		keys.K8 = AesX86.InverseMixColumns(roundKeys.K6);
		keys.K9 = AesX86.InverseMixColumns(roundKeys.K5);
		keys.K10 = AesX86.InverseMixColumns(roundKeys.K4);
		keys.K11 = AesX86.InverseMixColumns(roundKeys.K3);
		keys.K12 = AesX86.InverseMixColumns(roundKeys.K2);
		keys.K13 = AesX86.InverseMixColumns(roundKeys.K1);
		keys.K14 = roundKeys.K0;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static AesCipherX86 Create(ReadOnlySpan<byte> key)
	{
		return new AesCipherX86(key);
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
