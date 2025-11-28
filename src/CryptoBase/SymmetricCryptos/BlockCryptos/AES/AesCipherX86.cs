namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

internal readonly struct AesCipherX86 : IBlock16Cipher<AesCipherX86>
{
	public static bool IsSupported => AesX86.IsSupported && Sse2.IsSupported;

	private readonly int _keyLength;

	private readonly AesKeys _roundKeys;
	private readonly AesKeys _reverseRoundKeys;

	public void Dispose()
	{
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private AesCipherX86(in ReadOnlySpan<byte> key)
	{
		switch (key.Length)
		{
			case 16:
			{
				_keyLength = 11;
				ExpandKey128(key, ref _roundKeys);
				InverseExpandedKey128(_roundKeys, ref _reverseRoundKeys);
				break;
			}
			case 24:
			{
				_keyLength = 13;
				ExpandKey192(key, ref _roundKeys);
				InverseExpandedKey192(_roundKeys, ref _reverseRoundKeys);
				break;
			}
			case 32:
			{
				_keyLength = 15;
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
	private static void ExpandKey128(in ReadOnlySpan<byte> key, ref AesKeys roundKeys)
	{
		roundKeys.K0 = Unsafe.ReadUnaligned<Vector128<byte>>(in key.GetReference());

		roundKeys.K1 = KeyRound(roundKeys.K0, AesCipher.Rcon1);
		roundKeys.K2 = KeyRound(roundKeys.K1, AesCipher.Rcon2);
		roundKeys.K3 = KeyRound(roundKeys.K2, AesCipher.Rcon3);
		roundKeys.K4 = KeyRound(roundKeys.K3, AesCipher.Rcon4);
		roundKeys.K5 = KeyRound(roundKeys.K4, AesCipher.Rcon5);
		roundKeys.K6 = KeyRound(roundKeys.K5, AesCipher.Rcon6);
		roundKeys.K7 = KeyRound(roundKeys.K6, AesCipher.Rcon7);
		roundKeys.K8 = KeyRound(roundKeys.K7, AesCipher.Rcon8);
		roundKeys.K9 = KeyRound(roundKeys.K8, AesCipher.Rcon9);
		roundKeys.K10 = KeyRound(roundKeys.K9, AesCipher.Rcon10);

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
	private static void ExpandKey192(in ReadOnlySpan<byte> key, ref AesKeys roundKeys)
	{
		ref byte keyRef = ref key.GetReference();

		roundKeys.K12 = Unsafe.ReadUnaligned<Vector128<byte>>(in keyRef);// 0,15

		ref readonly ulong t = ref Unsafe.As<byte, ulong>(ref Unsafe.Add(ref keyRef, 16));
		Vector128<byte> t1 = Vector128.CreateScalar(t).AsByte();// 16,23

		KeyRound(out roundKeys.K0, out roundKeys.K1, out roundKeys.K2, ref roundKeys.K12, ref t1, AesCipher.Rcon1, AesCipher.Rcon2);
		KeyRound(out roundKeys.K3, out roundKeys.K4, out roundKeys.K5, ref roundKeys.K12, ref t1, AesCipher.Rcon3, AesCipher.Rcon4);
		KeyRound(out roundKeys.K6, out roundKeys.K7, out roundKeys.K8, ref roundKeys.K12, ref t1, AesCipher.Rcon5, AesCipher.Rcon6);
		KeyRound(out roundKeys.K9, out roundKeys.K10, out roundKeys.K11, ref roundKeys.K12, ref t1, AesCipher.Rcon7, AesCipher.Rcon8);

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

			b = Sse2.Shuffle(b.AsDouble(), t0.AsDouble(), 0).AsByte();
			c = Sse2.Shuffle(t0.AsDouble(), t1.AsDouble(), 1).AsByte();
			t2 = AesX86.KeygenAssist(t1, rcon1);
			KeyRound0(ref t0, ref t2, ref t1);
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ExpandKey256(in ReadOnlySpan<byte> key, ref AesKeys roundKeys)
	{
		ref byte keyRef = ref key.GetReference();

		roundKeys.K0 = roundKeys.K14 = Unsafe.ReadUnaligned<Vector128<byte>>(in keyRef);// 0,15
		roundKeys.K13 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref keyRef, 16));// 15,31

		KeyRound(out roundKeys.K1, out roundKeys.K2, ref roundKeys.K14, ref roundKeys.K13, AesCipher.Rcon1);
		KeyRound(out roundKeys.K3, out roundKeys.K4, ref roundKeys.K14, ref roundKeys.K13, AesCipher.Rcon2);
		KeyRound(out roundKeys.K5, out roundKeys.K6, ref roundKeys.K14, ref roundKeys.K13, AesCipher.Rcon3);
		KeyRound(out roundKeys.K7, out roundKeys.K8, ref roundKeys.K14, ref roundKeys.K13, AesCipher.Rcon4);
		KeyRound(out roundKeys.K9, out roundKeys.K10, ref roundKeys.K14, ref roundKeys.K13, AesCipher.Rcon5);
		KeyRound(out roundKeys.K11, out roundKeys.K12, ref roundKeys.K14, ref roundKeys.K13, AesCipher.Rcon6);

		Vector128<byte> t2 = AesX86.KeygenAssist(roundKeys.K13, AesCipher.Rcon7);
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
			Vector128<byte> t0 = AesX86.KeygenAssist(a, AesCipher.Rcon0);
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
	public static AesCipherX86 Create(in ReadOnlySpan<byte> key)
	{
		return new AesCipherX86(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer16 Encrypt(scoped in VectorBuffer16 source)
	{
		VectorBuffer16 r = source;

		r.V128 ^= _roundKeys.K0;
		r.V128 = AesX86.Encrypt(r.V128, _roundKeys.K1);
		r.V128 = AesX86.Encrypt(r.V128, _roundKeys.K2);
		r.V128 = AesX86.Encrypt(r.V128, _roundKeys.K3);
		r.V128 = AesX86.Encrypt(r.V128, _roundKeys.K4);
		r.V128 = AesX86.Encrypt(r.V128, _roundKeys.K5);
		r.V128 = AesX86.Encrypt(r.V128, _roundKeys.K6);
		r.V128 = AesX86.Encrypt(r.V128, _roundKeys.K7);
		r.V128 = AesX86.Encrypt(r.V128, _roundKeys.K8);
		r.V128 = AesX86.Encrypt(r.V128, _roundKeys.K9);

		if (_keyLength is 11)
		{
			r.V128 = AesX86.EncryptLast(r.V128, _roundKeys.K10);
			return r;
		}

		if (_keyLength >= 13)
		{
			r.V128 = AesX86.Encrypt(r.V128, _roundKeys.K10);
			r.V128 = AesX86.Encrypt(r.V128, _roundKeys.K11);
		}

		if (_keyLength is 13)
		{
			r.V128 = AesX86.EncryptLast(r.V128, _roundKeys.K12);
			return r;
		}

		r.V128 = AesX86.Encrypt(r.V128, _roundKeys.K12);
		r.V128 = AesX86.Encrypt(r.V128, _roundKeys.K13);
		r.V128 = AesX86.EncryptLast(r.V128, _roundKeys.K14);

		return r;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public VectorBuffer16 Decrypt(scoped in VectorBuffer16 source)
	{
		VectorBuffer16 r = source;

		r.V128 ^= _reverseRoundKeys.K0;
		r.V128 = AesX86.Decrypt(r.V128, _reverseRoundKeys.K1);
		r.V128 = AesX86.Decrypt(r.V128, _reverseRoundKeys.K2);
		r.V128 = AesX86.Decrypt(r.V128, _reverseRoundKeys.K3);
		r.V128 = AesX86.Decrypt(r.V128, _reverseRoundKeys.K4);
		r.V128 = AesX86.Decrypt(r.V128, _reverseRoundKeys.K5);
		r.V128 = AesX86.Decrypt(r.V128, _reverseRoundKeys.K6);
		r.V128 = AesX86.Decrypt(r.V128, _reverseRoundKeys.K7);
		r.V128 = AesX86.Decrypt(r.V128, _reverseRoundKeys.K8);
		r.V128 = AesX86.Decrypt(r.V128, _reverseRoundKeys.K9);

		if (_keyLength is 11)
		{
			r.V128 = AesX86.DecryptLast(r.V128, _reverseRoundKeys.K10);
			return r;
		}

		if (_keyLength >= 13)
		{
			r.V128 = AesX86.Decrypt(r.V128, _reverseRoundKeys.K10);
			r.V128 = AesX86.Decrypt(r.V128, _reverseRoundKeys.K11);
		}

		if (_keyLength is 13)
		{
			r.V128 = AesX86.DecryptLast(r.V128, _reverseRoundKeys.K12);
			return r;
		}

		r.V128 = AesX86.Decrypt(r.V128, _reverseRoundKeys.K12);
		r.V128 = AesX86.Decrypt(r.V128, _reverseRoundKeys.K13);
		r.V128 = AesX86.DecryptLast(r.V128, _reverseRoundKeys.K14);

		return r;
	}
}
