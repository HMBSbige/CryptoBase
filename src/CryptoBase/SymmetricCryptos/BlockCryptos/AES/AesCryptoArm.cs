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

		VectorBuffer16 value = Unsafe.ReadUnaligned<VectorBuffer16>(in source.GetReference());

		foreach (Vector128<byte> key in keys.Slice(0, keys.Length - 2))
		{
			EncryptPart(ref value.V128, key);
		}

		value.V128 = AesArm.Encrypt(value.V128, keys[^2]);
		value.V128 ^= keys[^1];

		Unsafe.WriteUnaligned(ref destination.GetReference(), value);
	}

	public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Decrypt(source, destination);

		Span<Vector128<byte>> keys = _inverseRoundKeys.Span;

		VectorBuffer16 value = Unsafe.ReadUnaligned<VectorBuffer16>(in source.GetReference());

		foreach (Vector128<byte> key in keys.Slice(0, keys.Length - 2))
		{
			DecryptPart(ref value.V128, key);
		}

		value.V128 = AesArm.Decrypt(value.V128, keys[^2]);
		value.V128 ^= keys[^1];

		Unsafe.WriteUnaligned(ref destination.GetReference(), value);
	}

	public override void Encrypt2(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 2 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 2 * BlockSize, nameof(destination));

		Span<Vector128<byte>> keys = _roundKeys.Span;

		VectorBuffer32 v = Unsafe.ReadUnaligned<VectorBuffer32>(ref source.GetReference());

		foreach (Vector128<byte> key in keys.Slice(0, keys.Length - 2))
		{
			EncryptPart(ref v.V128_0, key);
			EncryptPart(ref v.V128_1, key);
		}

		v.V128_0 = AesArm.Encrypt(v.V128_0, keys[^2]);
		v.V128_1 = AesArm.Encrypt(v.V128_1, keys[^2]);
		v.V128_0 ^= keys[^1];
		v.V128_1 ^= keys[^1];

		Unsafe.WriteUnaligned(ref destination.GetReference(), v);
	}

	public override void Decrypt2(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 2 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 2 * BlockSize, nameof(destination));

		Span<Vector128<byte>> keys = _inverseRoundKeys.Span;

		VectorBuffer32 v = Unsafe.ReadUnaligned<VectorBuffer32>(ref source.GetReference());

		foreach (Vector128<byte> key in keys.Slice(0, keys.Length - 2))
		{
			DecryptPart(ref v.V128_0, key);
			DecryptPart(ref v.V128_1, key);
		}

		v.V128_0 = AesArm.Decrypt(v.V128_0, keys[^2]);
		v.V128_1 = AesArm.Decrypt(v.V128_1, keys[^2]);
		v.V128_0 ^= keys[^1];
		v.V128_1 ^= keys[^1];

		Unsafe.WriteUnaligned(ref destination.GetReference(), v);
	}

	public override void Encrypt4(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 4 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 4 * BlockSize, nameof(destination));

		Span<Vector128<byte>> keys = _roundKeys.Span;

		VectorBuffer64 v = Unsafe.ReadUnaligned<VectorBuffer64>(ref source.GetReference());

		foreach (Vector128<byte> key in keys.Slice(0, keys.Length - 2))
		{
			EncryptPart(ref v.V128_0, key);
			EncryptPart(ref v.V128_1, key);
			EncryptPart(ref v.V128_2, key);
			EncryptPart(ref v.V128_3, key);
		}

		v.V128_0 = AesArm.Encrypt(v.V128_0, keys[^2]);
		v.V128_1 = AesArm.Encrypt(v.V128_1, keys[^2]);
		v.V128_2 = AesArm.Encrypt(v.V128_2, keys[^2]);
		v.V128_3 = AesArm.Encrypt(v.V128_3, keys[^2]);
		v.V128_0 ^= keys[^1];
		v.V128_1 ^= keys[^1];
		v.V128_2 ^= keys[^1];
		v.V128_3 ^= keys[^1];

		Unsafe.WriteUnaligned(ref destination.GetReference(), v);
	}

	public override void Decrypt4(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 4 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 4 * BlockSize, nameof(destination));

		Span<Vector128<byte>> keys = _inverseRoundKeys.Span;

		VectorBuffer64 v = Unsafe.ReadUnaligned<VectorBuffer64>(ref source.GetReference());

		foreach (Vector128<byte> key in keys.Slice(0, keys.Length - 2))
		{
			DecryptPart(ref v.V128_0, key);
			DecryptPart(ref v.V128_1, key);
			DecryptPart(ref v.V128_2, key);
			DecryptPart(ref v.V128_3, key);
		}

		v.V128_0 = AesArm.Decrypt(v.V128_0, keys[^2]);
		v.V128_1 = AesArm.Decrypt(v.V128_1, keys[^2]);
		v.V128_2 = AesArm.Decrypt(v.V128_2, keys[^2]);
		v.V128_3 = AesArm.Decrypt(v.V128_3, keys[^2]);
		v.V128_0 ^= keys[^1];
		v.V128_1 ^= keys[^1];
		v.V128_2 ^= keys[^1];
		v.V128_3 ^= keys[^1];

		Unsafe.WriteUnaligned(ref destination.GetReference(), v);
	}

	public override void Encrypt8(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 8 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 8 * BlockSize, nameof(destination));

		Span<Vector128<byte>> keys = _roundKeys.Span;

		VectorBuffer128 v = Unsafe.ReadUnaligned<VectorBuffer128>(ref source.GetReference());

		foreach (Vector128<byte> key in keys.Slice(0, keys.Length - 2))
		{
			EncryptPart(ref v.V128_0, key);
			EncryptPart(ref v.V128_1, key);
			EncryptPart(ref v.V128_2, key);
			EncryptPart(ref v.V128_3, key);
			EncryptPart(ref v.V128_4, key);
			EncryptPart(ref v.V128_5, key);
			EncryptPart(ref v.V128_6, key);
			EncryptPart(ref v.V128_7, key);
		}

		v.V128_0 = AesArm.Encrypt(v.V128_0, keys[^2]);
		v.V128_1 = AesArm.Encrypt(v.V128_1, keys[^2]);
		v.V128_2 = AesArm.Encrypt(v.V128_2, keys[^2]);
		v.V128_3 = AesArm.Encrypt(v.V128_3, keys[^2]);
		v.V128_4 = AesArm.Encrypt(v.V128_4, keys[^2]);
		v.V128_5 = AesArm.Encrypt(v.V128_5, keys[^2]);
		v.V128_6 = AesArm.Encrypt(v.V128_6, keys[^2]);
		v.V128_7 = AesArm.Encrypt(v.V128_7, keys[^2]);
		v.V128_0 ^= keys[^1];
		v.V128_1 ^= keys[^1];
		v.V128_2 ^= keys[^1];
		v.V128_3 ^= keys[^1];
		v.V128_4 ^= keys[^1];
		v.V128_5 ^= keys[^1];
		v.V128_6 ^= keys[^1];
		v.V128_7 ^= keys[^1];

		Unsafe.WriteUnaligned(ref destination.GetReference(), v);
	}

	public override void Decrypt8(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 8 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 8 * BlockSize, nameof(destination));

		Span<Vector128<byte>> keys = _inverseRoundKeys.Span;

		VectorBuffer128 v = Unsafe.ReadUnaligned<VectorBuffer128>(ref source.GetReference());

		foreach (Vector128<byte> key in keys.Slice(0, keys.Length - 2))
		{
			DecryptPart(ref v.V128_0, key);
			DecryptPart(ref v.V128_1, key);
			DecryptPart(ref v.V128_2, key);
			DecryptPart(ref v.V128_3, key);
			DecryptPart(ref v.V128_4, key);
			DecryptPart(ref v.V128_5, key);
			DecryptPart(ref v.V128_6, key);
			DecryptPart(ref v.V128_7, key);
		}

		v.V128_0 = AesArm.Decrypt(v.V128_0, keys[^2]);
		v.V128_1 = AesArm.Decrypt(v.V128_1, keys[^2]);
		v.V128_2 = AesArm.Decrypt(v.V128_2, keys[^2]);
		v.V128_3 = AesArm.Decrypt(v.V128_3, keys[^2]);
		v.V128_4 = AesArm.Decrypt(v.V128_4, keys[^2]);
		v.V128_5 = AesArm.Decrypt(v.V128_5, keys[^2]);
		v.V128_6 = AesArm.Decrypt(v.V128_6, keys[^2]);
		v.V128_7 = AesArm.Decrypt(v.V128_7, keys[^2]);
		v.V128_0 ^= keys[^1];
		v.V128_1 ^= keys[^1];
		v.V128_2 ^= keys[^1];
		v.V128_3 ^= keys[^1];
		v.V128_4 ^= keys[^1];
		v.V128_5 ^= keys[^1];
		v.V128_6 ^= keys[^1];
		v.V128_7 ^= keys[^1];

		Unsafe.WriteUnaligned(ref destination.GetReference(), v);
	}

	public override void Encrypt16(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 16 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 16 * BlockSize, nameof(destination));

		Span<Vector128<byte>> keys = _roundKeys.Span;

		VectorBuffer256 v = Unsafe.ReadUnaligned<VectorBuffer256>(ref source.GetReference());

		foreach (Vector128<byte> key in keys.Slice(0, keys.Length - 2))
		{
			EncryptPart(ref v.V128_0, key);
			EncryptPart(ref v.V128_1, key);
			EncryptPart(ref v.V128_2, key);
			EncryptPart(ref v.V128_3, key);
			EncryptPart(ref v.V128_4, key);
			EncryptPart(ref v.V128_5, key);
			EncryptPart(ref v.V128_6, key);
			EncryptPart(ref v.V128_7, key);
			EncryptPart(ref v.V128_8, key);
			EncryptPart(ref v.V128_9, key);
			EncryptPart(ref v.V128_10, key);
			EncryptPart(ref v.V128_11, key);
			EncryptPart(ref v.V128_12, key);
			EncryptPart(ref v.V128_13, key);
			EncryptPart(ref v.V128_14, key);
			EncryptPart(ref v.V128_15, key);
		}

		v.V128_0 = AesArm.Encrypt(v.V128_0, keys[^2]);
		v.V128_1 = AesArm.Encrypt(v.V128_1, keys[^2]);
		v.V128_2 = AesArm.Encrypt(v.V128_2, keys[^2]);
		v.V128_3 = AesArm.Encrypt(v.V128_3, keys[^2]);
		v.V128_4 = AesArm.Encrypt(v.V128_4, keys[^2]);
		v.V128_5 = AesArm.Encrypt(v.V128_5, keys[^2]);
		v.V128_6 = AesArm.Encrypt(v.V128_6, keys[^2]);
		v.V128_7 = AesArm.Encrypt(v.V128_7, keys[^2]);
		v.V128_8 = AesArm.Encrypt(v.V128_8, keys[^2]);
		v.V128_9 = AesArm.Encrypt(v.V128_9, keys[^2]);
		v.V128_10 = AesArm.Encrypt(v.V128_10, keys[^2]);
		v.V128_11 = AesArm.Encrypt(v.V128_11, keys[^2]);
		v.V128_12 = AesArm.Encrypt(v.V128_12, keys[^2]);
		v.V128_13 = AesArm.Encrypt(v.V128_13, keys[^2]);
		v.V128_14 = AesArm.Encrypt(v.V128_14, keys[^2]);
		v.V128_15 = AesArm.Encrypt(v.V128_15, keys[^2]);

		v.V128_0 ^= keys[^1];
		v.V128_1 ^= keys[^1];
		v.V128_2 ^= keys[^1];
		v.V128_3 ^= keys[^1];
		v.V128_4 ^= keys[^1];
		v.V128_5 ^= keys[^1];
		v.V128_6 ^= keys[^1];
		v.V128_7 ^= keys[^1];
		v.V128_8 ^= keys[^1];
		v.V128_9 ^= keys[^1];
		v.V128_10 ^= keys[^1];
		v.V128_11 ^= keys[^1];
		v.V128_12 ^= keys[^1];
		v.V128_13 ^= keys[^1];
		v.V128_14 ^= keys[^1];
		v.V128_15 ^= keys[^1];

		Unsafe.WriteUnaligned(ref destination.GetReference(), v);
	}

	public override void Decrypt16(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 16 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 16 * BlockSize, nameof(destination));

		Span<Vector128<byte>> keys = _inverseRoundKeys.Span;

		VectorBuffer256 v = Unsafe.ReadUnaligned<VectorBuffer256>(ref source.GetReference());

		foreach (Vector128<byte> key in keys.Slice(0, keys.Length - 2))
		{
			DecryptPart(ref v.V128_0, key);
			DecryptPart(ref v.V128_1, key);
			DecryptPart(ref v.V128_2, key);
			DecryptPart(ref v.V128_3, key);
			DecryptPart(ref v.V128_4, key);
			DecryptPart(ref v.V128_5, key);
			DecryptPart(ref v.V128_6, key);
			DecryptPart(ref v.V128_7, key);
			DecryptPart(ref v.V128_8, key);
			DecryptPart(ref v.V128_9, key);
			DecryptPart(ref v.V128_10, key);
			DecryptPart(ref v.V128_11, key);
			DecryptPart(ref v.V128_12, key);
			DecryptPart(ref v.V128_13, key);
			DecryptPart(ref v.V128_14, key);
			DecryptPart(ref v.V128_15, key);
		}

		v.V128_0 = AesArm.Decrypt(v.V128_0, keys[^2]);
		v.V128_1 = AesArm.Decrypt(v.V128_1, keys[^2]);
		v.V128_2 = AesArm.Decrypt(v.V128_2, keys[^2]);
		v.V128_3 = AesArm.Decrypt(v.V128_3, keys[^2]);
		v.V128_4 = AesArm.Decrypt(v.V128_4, keys[^2]);
		v.V128_5 = AesArm.Decrypt(v.V128_5, keys[^2]);
		v.V128_6 = AesArm.Decrypt(v.V128_6, keys[^2]);
		v.V128_7 = AesArm.Decrypt(v.V128_7, keys[^2]);
		v.V128_8 = AesArm.Decrypt(v.V128_8, keys[^2]);
		v.V128_9 = AesArm.Decrypt(v.V128_9, keys[^2]);
		v.V128_10 = AesArm.Decrypt(v.V128_10, keys[^2]);
		v.V128_11 = AesArm.Decrypt(v.V128_11, keys[^2]);
		v.V128_12 = AesArm.Decrypt(v.V128_12, keys[^2]);
		v.V128_13 = AesArm.Decrypt(v.V128_13, keys[^2]);
		v.V128_14 = AesArm.Decrypt(v.V128_14, keys[^2]);
		v.V128_15 = AesArm.Decrypt(v.V128_15, keys[^2]);

		v.V128_0 ^= keys[^1];
		v.V128_1 ^= keys[^1];
		v.V128_2 ^= keys[^1];
		v.V128_3 ^= keys[^1];
		v.V128_4 ^= keys[^1];
		v.V128_5 ^= keys[^1];
		v.V128_6 ^= keys[^1];
		v.V128_7 ^= keys[^1];
		v.V128_8 ^= keys[^1];
		v.V128_9 ^= keys[^1];
		v.V128_10 ^= keys[^1];
		v.V128_11 ^= keys[^1];
		v.V128_12 ^= keys[^1];
		v.V128_13 ^= keys[^1];
		v.V128_14 ^= keys[^1];
		v.V128_15 ^= keys[^1];

		Unsafe.WriteUnaligned(ref destination.GetReference(), v);
	}
}
