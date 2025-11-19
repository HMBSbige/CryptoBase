namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

public sealed class AesCryptoArm : AesCrypto
{
	public override BlockCryptoHardwareAcceleration HardwareAcceleration => BlockCryptoHardwareAcceleration.Block1 | BlockCryptoHardwareAcceleration.Block2 | BlockCryptoHardwareAcceleration.Block4 | BlockCryptoHardwareAcceleration.Block8 | BlockCryptoHardwareAcceleration.Block16;

	private readonly CryptoArrayPool<Vector128<byte>> _roundKeys;
	private readonly CryptoArrayPool<Vector128<byte>> _inverseRoundKeys;

	public AesCryptoArm(ReadOnlySpan<byte> key) : base(key)
	{
		int length = key.Length switch
		{
			16 => 11,
			24 => 13,
			32 => 15,
			_ => ThrowHelper.ThrowUnreachable<int>()
		};

		_roundKeys = new CryptoArrayPool<Vector128<byte>>(length);
		_inverseRoundKeys = new CryptoArrayPool<Vector128<byte>>(length);

		ExpandKey(key, _roundKeys.Span);
		InverseExpandedKey(_roundKeys.Span, _inverseRoundKeys.Span);
	}

	public override void Dispose()
	{
		_roundKeys.Dispose();
		_inverseRoundKeys.Dispose();
		base.Dispose();
	}

	private static void ExpandKey(ReadOnlySpan<byte> key, Span<Vector128<byte>> roundKeys)
	{
		Debug.Assert(key.Length is 16 && roundKeys.Length is 11 || key.Length is 24 && roundKeys.Length is 13 || key.Length is 32 && roundKeys.Length is 15);

		Span<uint> keys = MemoryMarshal.Cast<Vector128<byte>, uint>(roundKeys);
		key.CopyTo(MemoryMarshal.AsBytes(roundKeys));

		int nk = key.Length / sizeof(uint);

		for (int i = nk; i < roundKeys.Length * 4; ++i)
		{
			uint t = keys[i - 1];

			if (i % nk is 0)
			{
				t = SubWord(t).RotateRight(8) ^ Rcon[i / nk];
			}
			else if (nk > 6 && i % nk is 4)
			{
				t = SubWord(t);
			}

			keys[i] = keys[i - nk] ^ t;
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

	public override void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Encrypt(source, destination);

		Span<Vector128<byte>> keys = _roundKeys.Span;

		Vector128<byte> value = Unsafe.ReadUnaligned<Vector128<byte>>(in source.GetReference());

		foreach (Vector128<byte> key in keys.Slice(0, keys.Length - 2))
		{
			EncryptPart(ref value, key);
		}

		value = AesArm.Encrypt(value, keys[^2]);
		value ^= keys[^1];

		Unsafe.WriteUnaligned(ref destination.GetReference(), value);
	}

	public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Decrypt(source, destination);

		Span<Vector128<byte>> keys = _inverseRoundKeys.Span;

		Vector128<byte> value = Unsafe.ReadUnaligned<Vector128<byte>>(in source.GetReference());

		foreach (Vector128<byte> key in keys.Slice(0, keys.Length - 2))
		{
			DecryptPart(ref value, key);
		}

		value = AesArm.Decrypt(value, keys[^2]);
		value ^= keys[^1];

		Unsafe.WriteUnaligned(ref destination.GetReference(), value);
	}

	public override void Encrypt2(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 2 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 2 * BlockSize, nameof(destination));

		Span<Vector128<byte>> keys = _roundKeys.Span;

		Vector128X2<byte> v = Unsafe.ReadUnaligned<Vector128X2<byte>>(ref source.GetReference());

		foreach (Vector128<byte> key in keys.Slice(0, keys.Length - 2))
		{
			EncryptPart(ref v.V0, key);
			EncryptPart(ref v.V1, key);
		}

		v.V0 = AesArm.Encrypt(v.V0, keys[^2]);
		v.V1 = AesArm.Encrypt(v.V1, keys[^2]);
		v.V0 ^= keys[^1];
		v.V1 ^= keys[^1];

		Unsafe.WriteUnaligned(ref destination.GetReference(), v);
	}

	public override void Decrypt2(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 2 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 2 * BlockSize, nameof(destination));

		Span<Vector128<byte>> keys = _inverseRoundKeys.Span;

		Vector128X2<byte> v = Unsafe.ReadUnaligned<Vector128X2<byte>>(ref source.GetReference());

		foreach (Vector128<byte> key in keys.Slice(0, keys.Length - 2))
		{
			DecryptPart(ref v.V0, key);
			DecryptPart(ref v.V1, key);
		}

		v.V0 = AesArm.Decrypt(v.V0, keys[^2]);
		v.V1 = AesArm.Decrypt(v.V1, keys[^2]);
		v.V0 ^= keys[^1];
		v.V1 ^= keys[^1];

		Unsafe.WriteUnaligned(ref destination.GetReference(), v);
	}

	public override void Encrypt4(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 4 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 4 * BlockSize, nameof(destination));

		Span<Vector128<byte>> keys = _roundKeys.Span;

		Vector128X4<byte> v = Unsafe.ReadUnaligned<Vector128X4<byte>>(ref source.GetReference());

		foreach (Vector128<byte> key in keys.Slice(0, keys.Length - 2))
		{
			EncryptPart(ref v.V0, key);
			EncryptPart(ref v.V1, key);
			EncryptPart(ref v.V2, key);
			EncryptPart(ref v.V3, key);
		}

		v.V0 = AesArm.Encrypt(v.V0, keys[^2]);
		v.V1 = AesArm.Encrypt(v.V1, keys[^2]);
		v.V2 = AesArm.Encrypt(v.V2, keys[^2]);
		v.V3 = AesArm.Encrypt(v.V3, keys[^2]);
		v.V0 ^= keys[^1];
		v.V1 ^= keys[^1];
		v.V2 ^= keys[^1];
		v.V3 ^= keys[^1];

		Unsafe.WriteUnaligned(ref destination.GetReference(), v);
	}

	public override void Decrypt4(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 4 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 4 * BlockSize, nameof(destination));

		Span<Vector128<byte>> keys = _inverseRoundKeys.Span;

		Vector128X4<byte> v = Unsafe.ReadUnaligned<Vector128X4<byte>>(ref source.GetReference());

		foreach (Vector128<byte> key in keys.Slice(0, keys.Length - 2))
		{
			DecryptPart(ref v.V0, key);
			DecryptPart(ref v.V1, key);
			DecryptPart(ref v.V2, key);
			DecryptPart(ref v.V3, key);
		}

		v.V0 = AesArm.Decrypt(v.V0, keys[^2]);
		v.V1 = AesArm.Decrypt(v.V1, keys[^2]);
		v.V2 = AesArm.Decrypt(v.V2, keys[^2]);
		v.V3 = AesArm.Decrypt(v.V3, keys[^2]);
		v.V0 ^= keys[^1];
		v.V1 ^= keys[^1];
		v.V2 ^= keys[^1];
		v.V3 ^= keys[^1];

		Unsafe.WriteUnaligned(ref destination.GetReference(), v);
	}

	public override void Encrypt8(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 8 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 8 * BlockSize, nameof(destination));

		Span<Vector128<byte>> keys = _roundKeys.Span;

		Vector128X8<byte> v = Unsafe.ReadUnaligned<Vector128X8<byte>>(ref source.GetReference());

		foreach (Vector128<byte> key in keys.Slice(0, keys.Length - 2))
		{
			EncryptPart(ref v.V0, key);
			EncryptPart(ref v.V1, key);
			EncryptPart(ref v.V2, key);
			EncryptPart(ref v.V3, key);
			EncryptPart(ref v.V4, key);
			EncryptPart(ref v.V5, key);
			EncryptPart(ref v.V6, key);
			EncryptPart(ref v.V7, key);
		}

		v.V0 = AesArm.Encrypt(v.V0, keys[^2]);
		v.V1 = AesArm.Encrypt(v.V1, keys[^2]);
		v.V2 = AesArm.Encrypt(v.V2, keys[^2]);
		v.V3 = AesArm.Encrypt(v.V3, keys[^2]);
		v.V4 = AesArm.Encrypt(v.V4, keys[^2]);
		v.V5 = AesArm.Encrypt(v.V5, keys[^2]);
		v.V6 = AesArm.Encrypt(v.V6, keys[^2]);
		v.V7 = AesArm.Encrypt(v.V7, keys[^2]);
		v.V0 ^= keys[^1];
		v.V1 ^= keys[^1];
		v.V2 ^= keys[^1];
		v.V3 ^= keys[^1];
		v.V4 ^= keys[^1];
		v.V5 ^= keys[^1];
		v.V6 ^= keys[^1];
		v.V7 ^= keys[^1];

		Unsafe.WriteUnaligned(ref destination.GetReference(), v);
	}

	public override void Decrypt8(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 8 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 8 * BlockSize, nameof(destination));

		Span<Vector128<byte>> keys = _inverseRoundKeys.Span;

		Vector128X8<byte> v = Unsafe.ReadUnaligned<Vector128X8<byte>>(ref source.GetReference());

		foreach (Vector128<byte> key in keys.Slice(0, keys.Length - 2))
		{
			DecryptPart(ref v.V0, key);
			DecryptPart(ref v.V1, key);
			DecryptPart(ref v.V2, key);
			DecryptPart(ref v.V3, key);
			DecryptPart(ref v.V4, key);
			DecryptPart(ref v.V5, key);
			DecryptPart(ref v.V6, key);
			DecryptPart(ref v.V7, key);
		}

		v.V0 = AesArm.Decrypt(v.V0, keys[^2]);
		v.V1 = AesArm.Decrypt(v.V1, keys[^2]);
		v.V2 = AesArm.Decrypt(v.V2, keys[^2]);
		v.V3 = AesArm.Decrypt(v.V3, keys[^2]);
		v.V4 = AesArm.Decrypt(v.V4, keys[^2]);
		v.V5 = AesArm.Decrypt(v.V5, keys[^2]);
		v.V6 = AesArm.Decrypt(v.V6, keys[^2]);
		v.V7 = AesArm.Decrypt(v.V7, keys[^2]);
		v.V0 ^= keys[^1];
		v.V1 ^= keys[^1];
		v.V2 ^= keys[^1];
		v.V3 ^= keys[^1];
		v.V4 ^= keys[^1];
		v.V5 ^= keys[^1];
		v.V6 ^= keys[^1];
		v.V7 ^= keys[^1];

		Unsafe.WriteUnaligned(ref destination.GetReference(), v);
	}

	public override void Encrypt16(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 16 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 16 * BlockSize, nameof(destination));

		Span<Vector128<byte>> keys = _roundKeys.Span;

		Vector128X16<byte> v = Unsafe.ReadUnaligned<Vector128X16<byte>>(ref source.GetReference());

		foreach (Vector128<byte> key in keys.Slice(0, keys.Length - 2))
		{
			EncryptPart(ref v.V0, key);
			EncryptPart(ref v.V1, key);
			EncryptPart(ref v.V2, key);
			EncryptPart(ref v.V3, key);
			EncryptPart(ref v.V4, key);
			EncryptPart(ref v.V5, key);
			EncryptPart(ref v.V6, key);
			EncryptPart(ref v.V7, key);
			EncryptPart(ref v.V8, key);
			EncryptPart(ref v.V9, key);
			EncryptPart(ref v.V10, key);
			EncryptPart(ref v.V11, key);
			EncryptPart(ref v.V12, key);
			EncryptPart(ref v.V13, key);
			EncryptPart(ref v.V14, key);
			EncryptPart(ref v.V15, key);
		}

		v.V0 = AesArm.Encrypt(v.V0, keys[^2]);
		v.V1 = AesArm.Encrypt(v.V1, keys[^2]);
		v.V2 = AesArm.Encrypt(v.V2, keys[^2]);
		v.V3 = AesArm.Encrypt(v.V3, keys[^2]);
		v.V4 = AesArm.Encrypt(v.V4, keys[^2]);
		v.V5 = AesArm.Encrypt(v.V5, keys[^2]);
		v.V6 = AesArm.Encrypt(v.V6, keys[^2]);
		v.V7 = AesArm.Encrypt(v.V7, keys[^2]);
		v.V8 = AesArm.Encrypt(v.V8, keys[^2]);
		v.V9 = AesArm.Encrypt(v.V9, keys[^2]);
		v.V10 = AesArm.Encrypt(v.V10, keys[^2]);
		v.V11 = AesArm.Encrypt(v.V11, keys[^2]);
		v.V12 = AesArm.Encrypt(v.V12, keys[^2]);
		v.V13 = AesArm.Encrypt(v.V13, keys[^2]);
		v.V14 = AesArm.Encrypt(v.V14, keys[^2]);
		v.V15 = AesArm.Encrypt(v.V15, keys[^2]);

		v.V0 ^= keys[^1];
		v.V1 ^= keys[^1];
		v.V2 ^= keys[^1];
		v.V3 ^= keys[^1];
		v.V4 ^= keys[^1];
		v.V5 ^= keys[^1];
		v.V6 ^= keys[^1];
		v.V7 ^= keys[^1];
		v.V8 ^= keys[^1];
		v.V9 ^= keys[^1];
		v.V10 ^= keys[^1];
		v.V11 ^= keys[^1];
		v.V12 ^= keys[^1];
		v.V13 ^= keys[^1];
		v.V14 ^= keys[^1];
		v.V15 ^= keys[^1];

		Unsafe.WriteUnaligned(ref destination.GetReference(), v);
	}

	public override void Decrypt16(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 16 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 16 * BlockSize, nameof(destination));

		Span<Vector128<byte>> keys = _inverseRoundKeys.Span;

		Vector128X16<byte> v = Unsafe.ReadUnaligned<Vector128X16<byte>>(ref source.GetReference());

		foreach (Vector128<byte> key in keys.Slice(0, keys.Length - 2))
		{
			DecryptPart(ref v.V0, key);
			DecryptPart(ref v.V1, key);
			DecryptPart(ref v.V2, key);
			DecryptPart(ref v.V3, key);
			DecryptPart(ref v.V4, key);
			DecryptPart(ref v.V5, key);
			DecryptPart(ref v.V6, key);
			DecryptPart(ref v.V7, key);
			DecryptPart(ref v.V8, key);
			DecryptPart(ref v.V9, key);
			DecryptPart(ref v.V10, key);
			DecryptPart(ref v.V11, key);
			DecryptPart(ref v.V12, key);
			DecryptPart(ref v.V13, key);
			DecryptPart(ref v.V14, key);
			DecryptPart(ref v.V15, key);
		}

		v.V0 = AesArm.Decrypt(v.V0, keys[^2]);
		v.V1 = AesArm.Decrypt(v.V1, keys[^2]);
		v.V2 = AesArm.Decrypt(v.V2, keys[^2]);
		v.V3 = AesArm.Decrypt(v.V3, keys[^2]);
		v.V4 = AesArm.Decrypt(v.V4, keys[^2]);
		v.V5 = AesArm.Decrypt(v.V5, keys[^2]);
		v.V6 = AesArm.Decrypt(v.V6, keys[^2]);
		v.V7 = AesArm.Decrypt(v.V7, keys[^2]);
		v.V8 = AesArm.Decrypt(v.V8, keys[^2]);
		v.V9 = AesArm.Decrypt(v.V9, keys[^2]);
		v.V10 = AesArm.Decrypt(v.V10, keys[^2]);
		v.V11 = AesArm.Decrypt(v.V11, keys[^2]);
		v.V12 = AesArm.Decrypt(v.V12, keys[^2]);
		v.V13 = AesArm.Decrypt(v.V13, keys[^2]);
		v.V14 = AesArm.Decrypt(v.V14, keys[^2]);
		v.V15 = AesArm.Decrypt(v.V15, keys[^2]);

		v.V0 ^= keys[^1];
		v.V1 ^= keys[^1];
		v.V2 ^= keys[^1];
		v.V3 ^= keys[^1];
		v.V4 ^= keys[^1];
		v.V5 ^= keys[^1];
		v.V6 ^= keys[^1];
		v.V7 ^= keys[^1];
		v.V8 ^= keys[^1];
		v.V9 ^= keys[^1];
		v.V10 ^= keys[^1];
		v.V11 ^= keys[^1];
		v.V12 ^= keys[^1];
		v.V13 ^= keys[^1];
		v.V14 ^= keys[^1];
		v.V15 ^= keys[^1];

		Unsafe.WriteUnaligned(ref destination.GetReference(), v);
	}
}
