namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

public class Aes128CryptoX86 : AesCrypto
{
	public override BlockCryptoHardwareAcceleration HardwareAcceleration => BlockCryptoHardwareAcceleration.Block1 | BlockCryptoHardwareAcceleration.Block2 | BlockCryptoHardwareAcceleration.Block4 | BlockCryptoHardwareAcceleration.Block8;

	private Vector128<byte> _k0, _k1, _k2, _k3, _k4, _k5, _k6, _k7, _k8, _k9, _k10,
		_k11, _k12, _k13, _k14, _k15, _k16, _k17, _k18, _k19;

	public Aes128CryptoX86(ReadOnlySpan<byte> key) : base(key)
	{
		Init(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> KeyRound(Vector128<byte> key, [ConstantExpected] byte rcon)
	{
		Vector128<byte> t = AesX86.KeygenAssist(key, rcon);
		t = Sse2.Shuffle(t.AsUInt32(), 0b11_11_11_11).AsByte();

		key ^= Sse2.ShiftLeftLogical128BitLane(key, 4);
		key ^= Sse2.ShiftLeftLogical128BitLane(key, 8);

		return key ^ t;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void Init(ReadOnlySpan<byte> key)
	{
		_k0 = Unsafe.ReadUnaligned<Vector128<byte>>(in key.GetReference());
		_k1 = KeyRound(_k0, Rcon1);
		_k2 = KeyRound(_k1, Rcon2);
		_k3 = KeyRound(_k2, Rcon3);
		_k4 = KeyRound(_k3, Rcon4);
		_k5 = KeyRound(_k4, Rcon5);
		_k6 = KeyRound(_k5, Rcon6);
		_k7 = KeyRound(_k6, Rcon7);
		_k8 = KeyRound(_k7, Rcon8);
		_k9 = KeyRound(_k8, Rcon9);
		_k10 = KeyRound(_k9, Rcon10);

		_k11 = AesX86.InverseMixColumns(_k9);
		_k12 = AesX86.InverseMixColumns(_k8);
		_k13 = AesX86.InverseMixColumns(_k7);
		_k14 = AesX86.InverseMixColumns(_k6);
		_k15 = AesX86.InverseMixColumns(_k5);
		_k16 = AesX86.InverseMixColumns(_k4);
		_k17 = AesX86.InverseMixColumns(_k3);
		_k18 = AesX86.InverseMixColumns(_k2);
		_k19 = AesX86.InverseMixColumns(_k1);
	}

	public override VectorBuffer16 Encrypt(VectorBuffer16 source)
	{
		VectorBuffer16 t = source;

		t.V128 ^= _k0;
		t.V128 = AesX86.Encrypt(t.V128, _k1);
		t.V128 = AesX86.Encrypt(t.V128, _k2);
		t.V128 = AesX86.Encrypt(t.V128, _k3);
		t.V128 = AesX86.Encrypt(t.V128, _k4);
		t.V128 = AesX86.Encrypt(t.V128, _k5);
		t.V128 = AesX86.Encrypt(t.V128, _k6);
		t.V128 = AesX86.Encrypt(t.V128, _k7);
		t.V128 = AesX86.Encrypt(t.V128, _k8);
		t.V128 = AesX86.Encrypt(t.V128, _k9);
		t.V128 = AesX86.EncryptLast(t.V128, _k10);

		return t;
	}

	public override VectorBuffer16 Decrypt(VectorBuffer16 source)
	{
		VectorBuffer16 t = source;

		t.V128 ^= _k10;
		t.V128 = AesX86.Decrypt(t.V128, _k11);
		t.V128 = AesX86.Decrypt(t.V128, _k12);
		t.V128 = AesX86.Decrypt(t.V128, _k13);
		t.V128 = AesX86.Decrypt(t.V128, _k14);
		t.V128 = AesX86.Decrypt(t.V128, _k15);
		t.V128 = AesX86.Decrypt(t.V128, _k16);
		t.V128 = AesX86.Decrypt(t.V128, _k17);
		t.V128 = AesX86.Decrypt(t.V128, _k18);
		t.V128 = AesX86.Decrypt(t.V128, _k19);
		t.V128 = AesX86.DecryptLast(t.V128, _k0);

		return t;
	}

	public override void Encrypt2(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 2 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 2 * BlockSize, nameof(destination));

		ref byte s = ref source.GetReference();
		ref byte d = ref destination.GetReference();
		Vector128<byte> v0 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 0 * BlockSize));
		Vector128<byte> v1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 1 * BlockSize));

		v0 ^= _k0;
		v1 ^= _k0;

		v0 = AesX86.Encrypt(v0, _k1);
		v1 = AesX86.Encrypt(v1, _k1);

		v0 = AesX86.Encrypt(v0, _k2);
		v1 = AesX86.Encrypt(v1, _k2);

		v0 = AesX86.Encrypt(v0, _k3);
		v1 = AesX86.Encrypt(v1, _k3);

		v0 = AesX86.Encrypt(v0, _k4);
		v1 = AesX86.Encrypt(v1, _k4);

		v0 = AesX86.Encrypt(v0, _k5);
		v1 = AesX86.Encrypt(v1, _k5);

		v0 = AesX86.Encrypt(v0, _k6);
		v1 = AesX86.Encrypt(v1, _k6);

		v0 = AesX86.Encrypt(v0, _k7);
		v1 = AesX86.Encrypt(v1, _k7);

		v0 = AesX86.Encrypt(v0, _k8);
		v1 = AesX86.Encrypt(v1, _k8);

		v0 = AesX86.Encrypt(v0, _k9);
		v1 = AesX86.Encrypt(v1, _k9);

		v0 = AesX86.EncryptLast(v0, _k10);
		v1 = AesX86.EncryptLast(v1, _k10);

		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 0 * BlockSize), v0);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 1 * BlockSize), v1);
	}

	public override void Decrypt2(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 2 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 2 * BlockSize, nameof(destination));

		ref byte s = ref source.GetReference();
		ref byte d = ref destination.GetReference();

		Vector128<byte> v0 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 0 * BlockSize));
		Vector128<byte> v1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 1 * BlockSize));

		v0 ^= _k10;
		v1 ^= _k10;

		v0 = AesX86.Decrypt(v0, _k11);
		v1 = AesX86.Decrypt(v1, _k11);

		v0 = AesX86.Decrypt(v0, _k12);
		v1 = AesX86.Decrypt(v1, _k12);

		v0 = AesX86.Decrypt(v0, _k13);
		v1 = AesX86.Decrypt(v1, _k13);

		v0 = AesX86.Decrypt(v0, _k14);
		v1 = AesX86.Decrypt(v1, _k14);

		v0 = AesX86.Decrypt(v0, _k15);
		v1 = AesX86.Decrypt(v1, _k15);

		v0 = AesX86.Decrypt(v0, _k16);
		v1 = AesX86.Decrypt(v1, _k16);

		v0 = AesX86.Decrypt(v0, _k17);
		v1 = AesX86.Decrypt(v1, _k17);

		v0 = AesX86.Decrypt(v0, _k18);
		v1 = AesX86.Decrypt(v1, _k18);

		v0 = AesX86.Decrypt(v0, _k19);
		v1 = AesX86.Decrypt(v1, _k19);

		v0 = AesX86.DecryptLast(v0, _k0);
		v1 = AesX86.DecryptLast(v1, _k0);

		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 0 * BlockSize), v0);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 1 * BlockSize), v1);
	}

	public override void Encrypt4(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 4 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 4 * BlockSize, nameof(destination));

		ref byte s = ref source.GetReference();
		ref byte d = ref destination.GetReference();
		Vector128<byte> v0 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 0 * BlockSize));
		Vector128<byte> v1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 1 * BlockSize));
		Vector128<byte> v2 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 2 * BlockSize));
		Vector128<byte> v3 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 3 * BlockSize));

		v0 ^= _k0;
		v1 ^= _k0;
		v2 ^= _k0;
		v3 ^= _k0;

		v0 = AesX86.Encrypt(v0, _k1);
		v1 = AesX86.Encrypt(v1, _k1);
		v2 = AesX86.Encrypt(v2, _k1);
		v3 = AesX86.Encrypt(v3, _k1);

		v0 = AesX86.Encrypt(v0, _k2);
		v1 = AesX86.Encrypt(v1, _k2);
		v2 = AesX86.Encrypt(v2, _k2);
		v3 = AesX86.Encrypt(v3, _k2);

		v0 = AesX86.Encrypt(v0, _k3);
		v1 = AesX86.Encrypt(v1, _k3);
		v2 = AesX86.Encrypt(v2, _k3);
		v3 = AesX86.Encrypt(v3, _k3);

		v0 = AesX86.Encrypt(v0, _k4);
		v1 = AesX86.Encrypt(v1, _k4);
		v2 = AesX86.Encrypt(v2, _k4);
		v3 = AesX86.Encrypt(v3, _k4);

		v0 = AesX86.Encrypt(v0, _k5);
		v1 = AesX86.Encrypt(v1, _k5);
		v2 = AesX86.Encrypt(v2, _k5);
		v3 = AesX86.Encrypt(v3, _k5);

		v0 = AesX86.Encrypt(v0, _k6);
		v1 = AesX86.Encrypt(v1, _k6);
		v2 = AesX86.Encrypt(v2, _k6);
		v3 = AesX86.Encrypt(v3, _k6);

		v0 = AesX86.Encrypt(v0, _k7);
		v1 = AesX86.Encrypt(v1, _k7);
		v2 = AesX86.Encrypt(v2, _k7);
		v3 = AesX86.Encrypt(v3, _k7);

		v0 = AesX86.Encrypt(v0, _k8);
		v1 = AesX86.Encrypt(v1, _k8);
		v2 = AesX86.Encrypt(v2, _k8);
		v3 = AesX86.Encrypt(v3, _k8);

		v0 = AesX86.Encrypt(v0, _k9);
		v1 = AesX86.Encrypt(v1, _k9);
		v2 = AesX86.Encrypt(v2, _k9);
		v3 = AesX86.Encrypt(v3, _k9);

		v0 = AesX86.EncryptLast(v0, _k10);
		v1 = AesX86.EncryptLast(v1, _k10);
		v2 = AesX86.EncryptLast(v2, _k10);
		v3 = AesX86.EncryptLast(v3, _k10);

		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 0 * BlockSize), v0);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 1 * BlockSize), v1);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 2 * BlockSize), v2);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 3 * BlockSize), v3);
	}

	public override void Decrypt4(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 4 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 4 * BlockSize, nameof(destination));

		ref byte s = ref source.GetReference();
		ref byte d = ref destination.GetReference();

		Vector128<byte> v0 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 0 * BlockSize));
		Vector128<byte> v1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 1 * BlockSize));
		Vector128<byte> v2 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 2 * BlockSize));
		Vector128<byte> v3 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 3 * BlockSize));

		v0 ^= _k10;
		v1 ^= _k10;
		v2 ^= _k10;
		v3 ^= _k10;

		v0 = AesX86.Decrypt(v0, _k11);
		v1 = AesX86.Decrypt(v1, _k11);
		v2 = AesX86.Decrypt(v2, _k11);
		v3 = AesX86.Decrypt(v3, _k11);

		v0 = AesX86.Decrypt(v0, _k12);
		v1 = AesX86.Decrypt(v1, _k12);
		v2 = AesX86.Decrypt(v2, _k12);
		v3 = AesX86.Decrypt(v3, _k12);

		v0 = AesX86.Decrypt(v0, _k13);
		v1 = AesX86.Decrypt(v1, _k13);
		v2 = AesX86.Decrypt(v2, _k13);
		v3 = AesX86.Decrypt(v3, _k13);

		v0 = AesX86.Decrypt(v0, _k14);
		v1 = AesX86.Decrypt(v1, _k14);
		v2 = AesX86.Decrypt(v2, _k14);
		v3 = AesX86.Decrypt(v3, _k14);

		v0 = AesX86.Decrypt(v0, _k15);
		v1 = AesX86.Decrypt(v1, _k15);
		v2 = AesX86.Decrypt(v2, _k15);
		v3 = AesX86.Decrypt(v3, _k15);

		v0 = AesX86.Decrypt(v0, _k16);
		v1 = AesX86.Decrypt(v1, _k16);
		v2 = AesX86.Decrypt(v2, _k16);
		v3 = AesX86.Decrypt(v3, _k16);

		v0 = AesX86.Decrypt(v0, _k17);
		v1 = AesX86.Decrypt(v1, _k17);
		v2 = AesX86.Decrypt(v2, _k17);
		v3 = AesX86.Decrypt(v3, _k17);

		v0 = AesX86.Decrypt(v0, _k18);
		v1 = AesX86.Decrypt(v1, _k18);
		v2 = AesX86.Decrypt(v2, _k18);
		v3 = AesX86.Decrypt(v3, _k18);

		v0 = AesX86.Decrypt(v0, _k19);
		v1 = AesX86.Decrypt(v1, _k19);
		v2 = AesX86.Decrypt(v2, _k19);
		v3 = AesX86.Decrypt(v3, _k19);

		v0 = AesX86.DecryptLast(v0, _k0);
		v1 = AesX86.DecryptLast(v1, _k0);
		v2 = AesX86.DecryptLast(v2, _k0);
		v3 = AesX86.DecryptLast(v3, _k0);

		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 0 * BlockSize), v0);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 1 * BlockSize), v1);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 2 * BlockSize), v2);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 3 * BlockSize), v3);
	}

	public override void Encrypt8(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 8 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 8 * BlockSize, nameof(destination));

		ref byte s = ref source.GetReference();
		ref byte d = ref destination.GetReference();
		Vector128<byte> v0 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 0 * BlockSize));
		Vector128<byte> v1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 1 * BlockSize));
		Vector128<byte> v2 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 2 * BlockSize));
		Vector128<byte> v3 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 3 * BlockSize));
		Vector128<byte> v4 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 4 * BlockSize));
		Vector128<byte> v5 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 5 * BlockSize));
		Vector128<byte> v6 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 6 * BlockSize));
		Vector128<byte> v7 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 7 * BlockSize));

		v0 ^= _k0;
		v1 ^= _k0;
		v2 ^= _k0;
		v3 ^= _k0;
		v4 ^= _k0;
		v5 ^= _k0;
		v6 ^= _k0;
		v7 ^= _k0;

		v0 = AesX86.Encrypt(v0, _k1);
		v1 = AesX86.Encrypt(v1, _k1);
		v2 = AesX86.Encrypt(v2, _k1);
		v3 = AesX86.Encrypt(v3, _k1);
		v4 = AesX86.Encrypt(v4, _k1);
		v5 = AesX86.Encrypt(v5, _k1);
		v6 = AesX86.Encrypt(v6, _k1);
		v7 = AesX86.Encrypt(v7, _k1);

		v0 = AesX86.Encrypt(v0, _k2);
		v1 = AesX86.Encrypt(v1, _k2);
		v2 = AesX86.Encrypt(v2, _k2);
		v3 = AesX86.Encrypt(v3, _k2);
		v4 = AesX86.Encrypt(v4, _k2);
		v5 = AesX86.Encrypt(v5, _k2);
		v6 = AesX86.Encrypt(v6, _k2);
		v7 = AesX86.Encrypt(v7, _k2);

		v0 = AesX86.Encrypt(v0, _k3);
		v1 = AesX86.Encrypt(v1, _k3);
		v2 = AesX86.Encrypt(v2, _k3);
		v3 = AesX86.Encrypt(v3, _k3);
		v4 = AesX86.Encrypt(v4, _k3);
		v5 = AesX86.Encrypt(v5, _k3);
		v6 = AesX86.Encrypt(v6, _k3);
		v7 = AesX86.Encrypt(v7, _k3);

		v0 = AesX86.Encrypt(v0, _k4);
		v1 = AesX86.Encrypt(v1, _k4);
		v2 = AesX86.Encrypt(v2, _k4);
		v3 = AesX86.Encrypt(v3, _k4);
		v4 = AesX86.Encrypt(v4, _k4);
		v5 = AesX86.Encrypt(v5, _k4);
		v6 = AesX86.Encrypt(v6, _k4);
		v7 = AesX86.Encrypt(v7, _k4);

		v0 = AesX86.Encrypt(v0, _k5);
		v1 = AesX86.Encrypt(v1, _k5);
		v2 = AesX86.Encrypt(v2, _k5);
		v3 = AesX86.Encrypt(v3, _k5);
		v4 = AesX86.Encrypt(v4, _k5);
		v5 = AesX86.Encrypt(v5, _k5);
		v6 = AesX86.Encrypt(v6, _k5);
		v7 = AesX86.Encrypt(v7, _k5);

		v0 = AesX86.Encrypt(v0, _k6);
		v1 = AesX86.Encrypt(v1, _k6);
		v2 = AesX86.Encrypt(v2, _k6);
		v3 = AesX86.Encrypt(v3, _k6);
		v4 = AesX86.Encrypt(v4, _k6);
		v5 = AesX86.Encrypt(v5, _k6);
		v6 = AesX86.Encrypt(v6, _k6);
		v7 = AesX86.Encrypt(v7, _k6);

		v0 = AesX86.Encrypt(v0, _k7);
		v1 = AesX86.Encrypt(v1, _k7);
		v2 = AesX86.Encrypt(v2, _k7);
		v3 = AesX86.Encrypt(v3, _k7);
		v4 = AesX86.Encrypt(v4, _k7);
		v5 = AesX86.Encrypt(v5, _k7);
		v6 = AesX86.Encrypt(v6, _k7);
		v7 = AesX86.Encrypt(v7, _k7);

		v0 = AesX86.Encrypt(v0, _k8);
		v1 = AesX86.Encrypt(v1, _k8);
		v2 = AesX86.Encrypt(v2, _k8);
		v3 = AesX86.Encrypt(v3, _k8);
		v4 = AesX86.Encrypt(v4, _k8);
		v5 = AesX86.Encrypt(v5, _k8);
		v6 = AesX86.Encrypt(v6, _k8);
		v7 = AesX86.Encrypt(v7, _k8);

		v0 = AesX86.Encrypt(v0, _k9);
		v1 = AesX86.Encrypt(v1, _k9);
		v2 = AesX86.Encrypt(v2, _k9);
		v3 = AesX86.Encrypt(v3, _k9);
		v4 = AesX86.Encrypt(v4, _k9);
		v5 = AesX86.Encrypt(v5, _k9);
		v6 = AesX86.Encrypt(v6, _k9);
		v7 = AesX86.Encrypt(v7, _k9);

		v0 = AesX86.EncryptLast(v0, _k10);
		v1 = AesX86.EncryptLast(v1, _k10);
		v2 = AesX86.EncryptLast(v2, _k10);
		v3 = AesX86.EncryptLast(v3, _k10);
		v4 = AesX86.EncryptLast(v4, _k10);
		v5 = AesX86.EncryptLast(v5, _k10);
		v6 = AesX86.EncryptLast(v6, _k10);
		v7 = AesX86.EncryptLast(v7, _k10);

		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 0 * BlockSize), v0);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 1 * BlockSize), v1);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 2 * BlockSize), v2);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 3 * BlockSize), v3);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 4 * BlockSize), v4);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 5 * BlockSize), v5);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 6 * BlockSize), v6);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 7 * BlockSize), v7);
	}

	public override void Decrypt8(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 8 * BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, 8 * BlockSize, nameof(destination));

		ref byte s = ref source.GetReference();
		ref byte d = ref destination.GetReference();

		Vector128<byte> v0 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 0 * BlockSize));
		Vector128<byte> v1 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 1 * BlockSize));
		Vector128<byte> v2 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 2 * BlockSize));
		Vector128<byte> v3 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 3 * BlockSize));
		Vector128<byte> v4 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 4 * BlockSize));
		Vector128<byte> v5 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 5 * BlockSize));
		Vector128<byte> v6 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 6 * BlockSize));
		Vector128<byte> v7 = Unsafe.ReadUnaligned<Vector128<byte>>(ref Unsafe.Add(ref s, 7 * BlockSize));

		v0 ^= _k10;
		v1 ^= _k10;
		v2 ^= _k10;
		v3 ^= _k10;
		v4 ^= _k10;
		v5 ^= _k10;
		v6 ^= _k10;
		v7 ^= _k10;

		v0 = AesX86.Decrypt(v0, _k11);
		v1 = AesX86.Decrypt(v1, _k11);
		v2 = AesX86.Decrypt(v2, _k11);
		v3 = AesX86.Decrypt(v3, _k11);
		v4 = AesX86.Decrypt(v4, _k11);
		v5 = AesX86.Decrypt(v5, _k11);
		v6 = AesX86.Decrypt(v6, _k11);
		v7 = AesX86.Decrypt(v7, _k11);

		v0 = AesX86.Decrypt(v0, _k12);
		v1 = AesX86.Decrypt(v1, _k12);
		v2 = AesX86.Decrypt(v2, _k12);
		v3 = AesX86.Decrypt(v3, _k12);
		v4 = AesX86.Decrypt(v4, _k12);
		v5 = AesX86.Decrypt(v5, _k12);
		v6 = AesX86.Decrypt(v6, _k12);
		v7 = AesX86.Decrypt(v7, _k12);

		v0 = AesX86.Decrypt(v0, _k13);
		v1 = AesX86.Decrypt(v1, _k13);
		v2 = AesX86.Decrypt(v2, _k13);
		v3 = AesX86.Decrypt(v3, _k13);
		v4 = AesX86.Decrypt(v4, _k13);
		v5 = AesX86.Decrypt(v5, _k13);
		v6 = AesX86.Decrypt(v6, _k13);
		v7 = AesX86.Decrypt(v7, _k13);

		v0 = AesX86.Decrypt(v0, _k14);
		v1 = AesX86.Decrypt(v1, _k14);
		v2 = AesX86.Decrypt(v2, _k14);
		v3 = AesX86.Decrypt(v3, _k14);
		v4 = AesX86.Decrypt(v4, _k14);
		v5 = AesX86.Decrypt(v5, _k14);
		v6 = AesX86.Decrypt(v6, _k14);
		v7 = AesX86.Decrypt(v7, _k14);

		v0 = AesX86.Decrypt(v0, _k15);
		v1 = AesX86.Decrypt(v1, _k15);
		v2 = AesX86.Decrypt(v2, _k15);
		v3 = AesX86.Decrypt(v3, _k15);
		v4 = AesX86.Decrypt(v4, _k15);
		v5 = AesX86.Decrypt(v5, _k15);
		v6 = AesX86.Decrypt(v6, _k15);
		v7 = AesX86.Decrypt(v7, _k15);

		v0 = AesX86.Decrypt(v0, _k16);
		v1 = AesX86.Decrypt(v1, _k16);
		v2 = AesX86.Decrypt(v2, _k16);
		v3 = AesX86.Decrypt(v3, _k16);
		v4 = AesX86.Decrypt(v4, _k16);
		v5 = AesX86.Decrypt(v5, _k16);
		v6 = AesX86.Decrypt(v6, _k16);
		v7 = AesX86.Decrypt(v7, _k16);

		v0 = AesX86.Decrypt(v0, _k17);
		v1 = AesX86.Decrypt(v1, _k17);
		v2 = AesX86.Decrypt(v2, _k17);
		v3 = AesX86.Decrypt(v3, _k17);
		v4 = AesX86.Decrypt(v4, _k17);
		v5 = AesX86.Decrypt(v5, _k17);
		v6 = AesX86.Decrypt(v6, _k17);
		v7 = AesX86.Decrypt(v7, _k17);

		v0 = AesX86.Decrypt(v0, _k18);
		v1 = AesX86.Decrypt(v1, _k18);
		v2 = AesX86.Decrypt(v2, _k18);
		v3 = AesX86.Decrypt(v3, _k18);
		v4 = AesX86.Decrypt(v4, _k18);
		v5 = AesX86.Decrypt(v5, _k18);
		v6 = AesX86.Decrypt(v6, _k18);
		v7 = AesX86.Decrypt(v7, _k18);

		v0 = AesX86.Decrypt(v0, _k19);
		v1 = AesX86.Decrypt(v1, _k19);
		v2 = AesX86.Decrypt(v2, _k19);
		v3 = AesX86.Decrypt(v3, _k19);
		v4 = AesX86.Decrypt(v4, _k19);
		v5 = AesX86.Decrypt(v5, _k19);
		v6 = AesX86.Decrypt(v6, _k19);
		v7 = AesX86.Decrypt(v7, _k19);

		v0 = AesX86.DecryptLast(v0, _k0);
		v1 = AesX86.DecryptLast(v1, _k0);
		v2 = AesX86.DecryptLast(v2, _k0);
		v3 = AesX86.DecryptLast(v3, _k0);
		v4 = AesX86.DecryptLast(v4, _k0);
		v5 = AesX86.DecryptLast(v5, _k0);
		v6 = AesX86.DecryptLast(v6, _k0);
		v7 = AesX86.DecryptLast(v7, _k0);

		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 0 * BlockSize), v0);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 1 * BlockSize), v1);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 2 * BlockSize), v2);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 3 * BlockSize), v3);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 4 * BlockSize), v4);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 5 * BlockSize), v5);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 6 * BlockSize), v6);
		Unsafe.WriteUnaligned(ref Unsafe.Add(ref d, 7 * BlockSize), v7);
	}
}
