using System;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.AES
{
	public class Aes192CryptoX86 : AESCryptoX86
	{
		private Vector128<byte> _k0, _k1, _k2, _k3, _k4, _k5, _k6, _k7, _k8, _k9, _k10,
			_k11, _k12, _k13, _k14, _k15, _k16, _k17, _k18, _k19,
			_k20, _k21, _k22, _k23;

		public Aes192CryptoX86(byte[] key) : base(key)
		{
			Init();
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static void KeyRound(ref Vector128<byte> a, ref Vector128<byte> b, ref Vector128<byte> c)
		{
			var t = Sse2.ShiftLeftLogical128BitLane(a, 4);
			b = Sse2.Shuffle(b.AsUInt32(), 0b01_01_01_01).AsByte();
			a = Sse2.Xor(a, t);
			t = Sse2.ShiftLeftLogical128BitLane(t, 4);
			a = Sse2.Xor(a, t);
			t = Sse2.ShiftLeftLogical128BitLane(t, 4);
			a = Sse2.Xor(a, t);
			a = Sse2.Xor(a, b);
			b = Sse2.Shuffle(a.AsUInt32(), 0b11_11_11_11).AsByte();
			t = Sse2.ShiftLeftLogical128BitLane(c, 4);
			c = Sse2.Xor(c, t);
			c = Sse2.Xor(c, b);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static void KeyRound(
			out Vector128<byte> a, out Vector128<byte> b, out Vector128<byte> c,
			ref Vector128<byte> t0, ref Vector128<byte> t1,
			byte rcon0, byte rcon1)
		{
			a = t0;
			b = t1;
			var t2 = Aes.KeygenAssist(t1, rcon0);
			KeyRound(ref t0, ref t2, ref t1);

			b = Sse2.Shuffle(b.AsDouble(), t0.AsDouble(), 0).AsByte();
			c = Sse2.Shuffle(t0.AsDouble(), t1.AsDouble(), 1).AsByte();
			t2 = Aes.KeygenAssist(t1, rcon1);
			KeyRound(ref t0, ref t2, ref t1);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private unsafe void Init()
		{
			Vector128<byte> t0;
			Vector128<byte> t1;

			fixed (byte* p = Key.Span) // 24
			{
				t0 = Sse2.LoadVector128(p); // 0,15
				t1 = Vector128.Create(*(p + 16), *(p + 17), *(p + 18), *(p + 19), *(p + 20), *(p + 21), *(p + 22), *(p + 23), 0, 0, 0, 0, 0, 0, 0, 0);
			}

			KeyRound(out _k0, out _k1, out _k2, ref t0, ref t1, Rcon[1], Rcon[2]);
			KeyRound(out _k3, out _k4, out _k5, ref t0, ref t1, Rcon[3], Rcon[4]);
			KeyRound(out _k6, out _k7, out _k8, ref t0, ref t1, Rcon[5], Rcon[6]);
			KeyRound(out _k9, out _k10, out _k11, ref t0, ref t1, Rcon[7], Rcon[8]);
			_k12 = t0;

			_k13 = Aes.InverseMixColumns(_k11);
			_k14 = Aes.InverseMixColumns(_k10);
			_k15 = Aes.InverseMixColumns(_k9);
			_k16 = Aes.InverseMixColumns(_k8);
			_k17 = Aes.InverseMixColumns(_k7);
			_k18 = Aes.InverseMixColumns(_k6);
			_k19 = Aes.InverseMixColumns(_k5);
			_k20 = Aes.InverseMixColumns(_k4);
			_k21 = Aes.InverseMixColumns(_k3);
			_k22 = Aes.InverseMixColumns(_k2);
			_k23 = Aes.InverseMixColumns(_k1);
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
			t = Aes.Encrypt(t, _k10);
			t = Aes.Encrypt(t, _k11);
			t = Aes.EncryptLast(t, _k12);

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

			t = Sse2.Xor(t, _k12);
			t = Aes.Decrypt(t, _k13);
			t = Aes.Decrypt(t, _k14);
			t = Aes.Decrypt(t, _k15);
			t = Aes.Decrypt(t, _k16);
			t = Aes.Decrypt(t, _k17);
			t = Aes.Decrypt(t, _k18);
			t = Aes.Decrypt(t, _k19);
			t = Aes.Decrypt(t, _k20);
			t = Aes.Decrypt(t, _k21);
			t = Aes.Decrypt(t, _k22);
			t = Aes.Decrypt(t, _k23);
			t = Aes.DecryptLast(t, _k0);

			fixed (byte* d = destination)
			{
				Sse2.Store(d, t);
			}
		}
	}
}
