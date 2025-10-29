namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

public class Aes128CryptoX86 : AesCrypto
{
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

	public override void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Encrypt(source, destination);

		Vector128<byte> t = Unsafe.ReadUnaligned<Vector128<byte>>(in source.GetReference());

		t ^= _k0;
		t = AesX86.Encrypt(t, _k1);
		t = AesX86.Encrypt(t, _k2);
		t = AesX86.Encrypt(t, _k3);
		t = AesX86.Encrypt(t, _k4);
		t = AesX86.Encrypt(t, _k5);
		t = AesX86.Encrypt(t, _k6);
		t = AesX86.Encrypt(t, _k7);
		t = AesX86.Encrypt(t, _k8);
		t = AesX86.Encrypt(t, _k9);
		t = AesX86.EncryptLast(t, _k10);

		Unsafe.WriteUnaligned(ref destination.GetReference(), t);
	}

	public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Decrypt(source, destination);

		Vector128<byte> t = Unsafe.ReadUnaligned<Vector128<byte>>(in source.GetReference());

		t ^= _k10;
		t = AesX86.Decrypt(t, _k11);
		t = AesX86.Decrypt(t, _k12);
		t = AesX86.Decrypt(t, _k13);
		t = AesX86.Decrypt(t, _k14);
		t = AesX86.Decrypt(t, _k15);
		t = AesX86.Decrypt(t, _k16);
		t = AesX86.Decrypt(t, _k17);
		t = AesX86.Decrypt(t, _k18);
		t = AesX86.Decrypt(t, _k19);
		t = AesX86.DecryptLast(t, _k0);

		Unsafe.WriteUnaligned(ref destination.GetReference(), t);
	}
}
