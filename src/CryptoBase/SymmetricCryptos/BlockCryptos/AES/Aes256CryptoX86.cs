namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

public class Aes256CryptoX86 : AESCryptoX86
{
	private Vector128<byte> _k0,
		_k1,
		_k2,
		_k3,
		_k4,
		_k5,
		_k6,
		_k7,
		_k8,
		_k9,
		_k10,
		_k11,
		_k12,
		_k13,
		_k14,
		_k15,
		_k16,
		_k17,
		_k18,
		_k19,
		_k20,
		_k21,
		_k22,
		_k23,
		_k24,
		_k25,
		_k26,
		_k27;

	public Aes256CryptoX86(ReadOnlySpan<byte> key) : base(key)
	{
		Init(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void KeyRound1(ref Vector128<byte> a, ref Vector128<byte> b)
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
	private static void KeyRound2(ref Vector128<byte> a, ref Vector128<byte> b)
	{
		Vector128<byte> t0 = Aes.KeygenAssist(a, AESUtils.Rcon0);
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
	private static void KeyRound(out Vector128<byte> a, out Vector128<byte> b,
		ref Vector128<byte> t0, ref Vector128<byte> t1, [ConstantExpected] byte rcon)
	{
		a = t1;
		Vector128<byte> t2 = Aes.KeygenAssist(t1, rcon);
		KeyRound1(ref t0, ref t2);
		b = t0;
		KeyRound2(ref t0, ref t1);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private void Init(ReadOnlySpan<byte> key)
	{
		Vector128<byte> t0 = Vector128.Create(key);// 0,15
		Vector128<byte> t1 = Vector128.Create(key[16..]);// 15,31

		_k0 = t0;

		KeyRound(out _k1, out _k2, ref t0, ref t1, AESUtils.Rcon1);
		KeyRound(out _k3, out _k4, ref t0, ref t1, AESUtils.Rcon2);
		KeyRound(out _k5, out _k6, ref t0, ref t1, AESUtils.Rcon3);
		KeyRound(out _k7, out _k8, ref t0, ref t1, AESUtils.Rcon4);
		KeyRound(out _k9, out _k10, ref t0, ref t1, AESUtils.Rcon5);
		KeyRound(out _k11, out _k12, ref t0, ref t1, AESUtils.Rcon6);

		_k13 = t1;
		Vector128<byte> t2 = Aes.KeygenAssist(t1, AESUtils.Rcon7);
		KeyRound1(ref t0, ref t2);
		_k14 = t0;

		_k15 = Aes.InverseMixColumns(_k13);
		_k16 = Aes.InverseMixColumns(_k12);
		_k17 = Aes.InverseMixColumns(_k11);
		_k18 = Aes.InverseMixColumns(_k10);
		_k19 = Aes.InverseMixColumns(_k9);
		_k20 = Aes.InverseMixColumns(_k8);
		_k21 = Aes.InverseMixColumns(_k7);
		_k22 = Aes.InverseMixColumns(_k6);
		_k23 = Aes.InverseMixColumns(_k5);
		_k24 = Aes.InverseMixColumns(_k4);
		_k25 = Aes.InverseMixColumns(_k3);
		_k26 = Aes.InverseMixColumns(_k2);
		_k27 = Aes.InverseMixColumns(_k1);
	}

	public override void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Encrypt(source, destination);

		Vector128<byte> t = Vector128.Create(source);

		t ^= _k0;
		t = Aes.Encrypt(t, _k1);
		t = Aes.Encrypt(t, _k2);
		t = Aes.Encrypt(t, _k3);
		t = Aes.Encrypt(t, _k4);
		t = Aes.Encrypt(t, _k5);
		t = Aes.Encrypt(t, _k6);
		t = Aes.Encrypt(t, _k7);
		t = Aes.Encrypt(t, _k8);
		t = Aes.Encrypt(t, _k9);
		t = Aes.Encrypt(t, _k10);
		t = Aes.Encrypt(t, _k11);
		t = Aes.Encrypt(t, _k12);
		t = Aes.Encrypt(t, _k13);
		t = Aes.EncryptLast(t, _k14);

		t.CopyTo(destination);
	}

	public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Decrypt(source, destination);

		Vector128<byte> t = Vector128.Create(source);

		t ^= _k14;
		t = Aes.Decrypt(t, _k15);
		t = Aes.Decrypt(t, _k16);
		t = Aes.Decrypt(t, _k17);
		t = Aes.Decrypt(t, _k18);
		t = Aes.Decrypt(t, _k19);
		t = Aes.Decrypt(t, _k20);
		t = Aes.Decrypt(t, _k21);
		t = Aes.Decrypt(t, _k22);
		t = Aes.Decrypt(t, _k23);
		t = Aes.Decrypt(t, _k24);
		t = Aes.Decrypt(t, _k25);
		t = Aes.Decrypt(t, _k26);
		t = Aes.Decrypt(t, _k27);
		t = Aes.DecryptLast(t, _k0);

		t.CopyTo(destination);
	}
}
