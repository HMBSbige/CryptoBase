using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES;

public class Aes128CryptoX86 : AESCryptoX86
{
	private Vector128<byte> _k0, _k1, _k2, _k3, _k4, _k5, _k6, _k7, _k8, _k9, _k10,
		_k11, _k12, _k13, _k14, _k15, _k16, _k17, _k18, _k19;

	public Aes128CryptoX86(ReadOnlySpan<byte> key) : base(key)
	{
		Init(key);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> KeyRound(Vector128<byte> key, byte rcon)
	{
		var t = Aes.KeygenAssist(key, rcon);
		t = Sse2.Shuffle(t.AsUInt32(), 0b11_11_11_11).AsByte();

		key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 4));
		key = Sse2.Xor(key, Sse2.ShiftLeftLogical128BitLane(key, 8));

		return Sse2.Xor(key, t);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private unsafe void Init(ReadOnlySpan<byte> key)
	{
		fixed (byte* p = key)
		{
			_k0 = Sse2.LoadVector128(p);
		}

		_k1 = KeyRound(_k0, Rcon[1]);
		_k2 = KeyRound(_k1, Rcon[2]);
		_k3 = KeyRound(_k2, Rcon[3]);
		_k4 = KeyRound(_k3, Rcon[4]);
		_k5 = KeyRound(_k4, Rcon[5]);
		_k6 = KeyRound(_k5, Rcon[6]);
		_k7 = KeyRound(_k6, Rcon[7]);
		_k8 = KeyRound(_k7, Rcon[8]);
		_k9 = KeyRound(_k8, Rcon[9]);
		_k10 = KeyRound(_k9, Rcon[10]);

		_k11 = Aes.InverseMixColumns(_k9);
		_k12 = Aes.InverseMixColumns(_k8);
		_k13 = Aes.InverseMixColumns(_k7);
		_k14 = Aes.InverseMixColumns(_k6);
		_k15 = Aes.InverseMixColumns(_k5);
		_k16 = Aes.InverseMixColumns(_k4);
		_k17 = Aes.InverseMixColumns(_k3);
		_k18 = Aes.InverseMixColumns(_k2);
		_k19 = Aes.InverseMixColumns(_k1);
	}

	public override unsafe void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Encrypt(source, destination);

		Vector128<byte> t;

		fixed (byte* s = source)
		{
			t = Sse2.LoadVector128(s);
		}

		t = Sse2.Xor(t, _k0);
		t = Aes.Encrypt(t, _k1);
		t = Aes.Encrypt(t, _k2);
		t = Aes.Encrypt(t, _k3);
		t = Aes.Encrypt(t, _k4);
		t = Aes.Encrypt(t, _k5);
		t = Aes.Encrypt(t, _k6);
		t = Aes.Encrypt(t, _k7);
		t = Aes.Encrypt(t, _k8);
		t = Aes.Encrypt(t, _k9);
		t = Aes.EncryptLast(t, _k10);

		fixed (byte* d = destination)
		{
			Sse2.Store(d, t);
		}
	}

	public override unsafe void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		base.Decrypt(source, destination);

		Vector128<byte> t;

		fixed (byte* s = source)
		{
			t = Sse2.LoadVector128(s);
		}

		t = Sse2.Xor(t, _k10);
		t = Aes.Decrypt(t, _k11);
		t = Aes.Decrypt(t, _k12);
		t = Aes.Decrypt(t, _k13);
		t = Aes.Decrypt(t, _k14);
		t = Aes.Decrypt(t, _k15);
		t = Aes.Decrypt(t, _k16);
		t = Aes.Decrypt(t, _k17);
		t = Aes.Decrypt(t, _k18);
		t = Aes.Decrypt(t, _k19);
		t = Aes.DecryptLast(t, _k0);

		fixed (byte* d = destination)
		{
			Sse2.Store(d, t);
		}
	}
}
