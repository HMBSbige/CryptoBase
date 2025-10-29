namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

public class Aes192CryptoX86 : AesCrypto
{
	private Vector128<byte> _k0, _k1, _k2, _k3, _k4, _k5, _k6, _k7, _k8, _k9, _k10,
		_k11, _k12, _k13, _k14, _k15, _k16, _k17, _k18, _k19,
		_k20, _k21, _k22, _k23;

	public Aes192CryptoX86(ReadOnlySpan<byte> key) : base(key)
	{
		Init(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void KeyRound(ref Vector128<byte> a, ref Vector128<byte> b, ref Vector128<byte> c)
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
	private static void KeyRound(
		out Vector128<byte> a, out Vector128<byte> b, out Vector128<byte> c,
		ref Vector128<byte> t0, ref Vector128<byte> t1,
		[ConstantExpected] byte rcon0, [ConstantExpected] byte rcon1)
	{
		a = t0;
		b = t1;
		Vector128<byte> t2 = AesX86.KeygenAssist(t1, rcon0);
		KeyRound(ref t0, ref t2, ref t1);

		b = Sse2.Shuffle(b.AsDouble(), t0.AsDouble(), 0).AsByte();
		c = Sse2.Shuffle(t0.AsDouble(), t1.AsDouble(), 1).AsByte();
		t2 = AesX86.KeygenAssist(t1, rcon1);
		KeyRound(ref t0, ref t2, ref t1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void Init(ReadOnlySpan<byte> key)
	{
		ref byte keyRef = ref key.GetReference();

		Vector128<byte> t0 = Unsafe.ReadUnaligned<Vector128<byte>>(in keyRef);// 0,15

		ref readonly ulong t = ref Unsafe.As<byte, ulong>(ref Unsafe.Add(ref keyRef, 16));
		Vector128<byte> t1 = Vector128.Create(t, 0).AsByte();// 16,23

		KeyRound(out _k0, out _k1, out _k2, ref t0, ref t1, Rcon1, Rcon2);
		KeyRound(out _k3, out _k4, out _k5, ref t0, ref t1, Rcon3, Rcon4);
		KeyRound(out _k6, out _k7, out _k8, ref t0, ref t1, Rcon5, Rcon6);
		KeyRound(out _k9, out _k10, out _k11, ref t0, ref t1, Rcon7, Rcon8);
		_k12 = t0;

		_k13 = AesX86.InverseMixColumns(_k11);
		_k14 = AesX86.InverseMixColumns(_k10);
		_k15 = AesX86.InverseMixColumns(_k9);
		_k16 = AesX86.InverseMixColumns(_k8);
		_k17 = AesX86.InverseMixColumns(_k7);
		_k18 = AesX86.InverseMixColumns(_k6);
		_k19 = AesX86.InverseMixColumns(_k5);
		_k20 = AesX86.InverseMixColumns(_k4);
		_k21 = AesX86.InverseMixColumns(_k3);
		_k22 = AesX86.InverseMixColumns(_k2);
		_k23 = AesX86.InverseMixColumns(_k1);
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
		t = AesX86.Encrypt(t, _k10);
		t = AesX86.Encrypt(t, _k11);
		t = AesX86.EncryptLast(t, _k12);

		Unsafe.WriteUnaligned(ref destination.GetReference(), t);
	}

	public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Decrypt(source, destination);

		Vector128<byte> t = Unsafe.ReadUnaligned<Vector128<byte>>(in source.GetReference());

		t ^= _k12;
		t = AesX86.Decrypt(t, _k13);
		t = AesX86.Decrypt(t, _k14);
		t = AesX86.Decrypt(t, _k15);
		t = AesX86.Decrypt(t, _k16);
		t = AesX86.Decrypt(t, _k17);
		t = AesX86.Decrypt(t, _k18);
		t = AesX86.Decrypt(t, _k19);
		t = AesX86.Decrypt(t, _k20);
		t = AesX86.Decrypt(t, _k21);
		t = AesX86.Decrypt(t, _k22);
		t = AesX86.Decrypt(t, _k23);
		t = AesX86.DecryptLast(t, _k0);

		Unsafe.WriteUnaligned(ref destination.GetReference(), t);
	}
}
