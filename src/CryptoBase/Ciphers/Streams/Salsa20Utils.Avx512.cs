namespace CryptoBase.Ciphers.Streams;

internal static partial class Salsa20Utils
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void QuarterRound(ref Vector512<byte> a, ref Vector512<byte> b, ref Vector512<byte> c, ref Vector512<byte> d)
	{
		a ^= (b.AsUInt32() + c.AsUInt32()).RotateLeftUInt32(7).AsByte();
		d ^= (a.AsUInt32() + b.AsUInt32()).RotateLeftUInt32(9).AsByte();
		c ^= (d.AsUInt32() + a.AsUInt32()).RotateLeftUInt32(13).AsByte();
		b ^= (c.AsUInt32() + d.AsUInt32()).RotateLeftUInt32(18).AsByte();
	}

	[SkipLocalsInit]
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static int SalsaCoreSoa1024Avx512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int offset = 0;
		int length = source.Length;

		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte dstRef = ref destination.GetReference();

		ref ulong counter = ref GetCounter(ref stateRef);

		Vector512<byte> o0 = Vector512.Create(Unsafe.Add(ref stateRef, 0)).AsByte();
		Vector512<byte> o1 = Vector512.Create(Unsafe.Add(ref stateRef, 1)).AsByte();
		Vector512<byte> o2 = Vector512.Create(Unsafe.Add(ref stateRef, 2)).AsByte();
		Vector512<byte> o3 = Vector512.Create(Unsafe.Add(ref stateRef, 3)).AsByte();
		Vector512<byte> o4 = Vector512.Create(Unsafe.Add(ref stateRef, 4)).AsByte();
		Vector512<byte> o5 = Vector512.Create(Unsafe.Add(ref stateRef, 5)).AsByte();
		Vector512<byte> o6 = Vector512.Create(Unsafe.Add(ref stateRef, 6)).AsByte();
		Vector512<byte> o7 = Vector512.Create(Unsafe.Add(ref stateRef, 7)).AsByte();
		// 8
		// 9
		Vector512<byte> o10 = Vector512.Create(Unsafe.Add(ref stateRef, 10)).AsByte();
		Vector512<byte> o11 = Vector512.Create(Unsafe.Add(ref stateRef, 11)).AsByte();
		Vector512<byte> o12 = Vector512.Create(Unsafe.Add(ref stateRef, 12)).AsByte();
		Vector512<byte> o13 = Vector512.Create(Unsafe.Add(ref stateRef, 13)).AsByte();
		Vector512<byte> o14 = Vector512.Create(Unsafe.Add(ref stateRef, 14)).AsByte();
		Vector512<byte> o15 = Vector512.Create(Unsafe.Add(ref stateRef, 15)).AsByte();

		while (length >= 1024)
		{
			ref byte s = ref Unsafe.Add(ref sourceRef, offset);

			ChaCha20Utils.AddAndTranspose(counter, out Vector512<byte> o8, out Vector512<byte> o9);
			Vector512<byte> x0 = o0;
			Vector512<byte> x1 = o1;
			Vector512<byte> x2 = o2;
			Vector512<byte> x3 = o3;
			Vector512<byte> x4 = o4;
			Vector512<byte> x5 = o5;
			Vector512<byte> x6 = o6;
			Vector512<byte> x7 = o7;
			Vector512<byte> x8 = o8;
			Vector512<byte> x9 = o9;
			Vector512<byte> x10 = o10;
			Vector512<byte> x11 = o11;
			Vector512<byte> x12 = o12;
			Vector512<byte> x13 = o13;
			Vector512<byte> x14 = o14;
			Vector512<byte> x15 = o15;

			for (int i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x4, ref x0, ref x12, ref x8);
				QuarterRound(ref x9, ref x5, ref x1, ref x13);
				QuarterRound(ref x14, ref x10, ref x6, ref x2);
				QuarterRound(ref x3, ref x15, ref x11, ref x7);

				QuarterRound(ref x1, ref x0, ref x3, ref x2);
				QuarterRound(ref x6, ref x5, ref x4, ref x7);
				QuarterRound(ref x11, ref x10, ref x9, ref x8);
				QuarterRound(ref x12, ref x15, ref x14, ref x13);
			}

			x0 = (x0.AsUInt32() + o0.AsUInt32()).AsByte();
			x1 = (x1.AsUInt32() + o1.AsUInt32()).AsByte();
			x2 = (x2.AsUInt32() + o2.AsUInt32()).AsByte();
			x3 = (x3.AsUInt32() + o3.AsUInt32()).AsByte();
			x4 = (x4.AsUInt32() + o4.AsUInt32()).AsByte();
			x5 = (x5.AsUInt32() + o5.AsUInt32()).AsByte();
			x6 = (x6.AsUInt32() + o6.AsUInt32()).AsByte();
			x7 = (x7.AsUInt32() + o7.AsUInt32()).AsByte();
			x8 = (x8.AsUInt32() + o8.AsUInt32()).AsByte();
			x9 = (x9.AsUInt32() + o9.AsUInt32()).AsByte();
			x10 = (x10.AsUInt32() + o10.AsUInt32()).AsByte();
			x11 = (x11.AsUInt32() + o11.AsUInt32()).AsByte();
			x12 = (x12.AsUInt32() + o12.AsUInt32()).AsByte();
			x13 = (x13.AsUInt32() + o13.AsUInt32()).AsByte();
			x14 = (x14.AsUInt32() + o14.AsUInt32()).AsByte();
			x15 = (x15.AsUInt32() + o15.AsUInt32()).AsByte();

			VectorTranspose.Transpose(ref x0, ref x1, ref x2, ref x3, ref x4, ref x5, ref x6, ref x7, ref x8, ref x9, ref x10, ref x11, ref x12, ref x13, ref x14, ref x15);

			x0 ^= Vector512.LoadUnsafe(ref s, 0);
			x1 ^= Vector512.LoadUnsafe(ref s, 64);
			x2 ^= Vector512.LoadUnsafe(ref s, 128);
			x3 ^= Vector512.LoadUnsafe(ref s, 192);
			x4 ^= Vector512.LoadUnsafe(ref s, 256);
			x5 ^= Vector512.LoadUnsafe(ref s, 320);
			x6 ^= Vector512.LoadUnsafe(ref s, 384);
			x7 ^= Vector512.LoadUnsafe(ref s, 448);
			x8 ^= Vector512.LoadUnsafe(ref s, 512);
			x9 ^= Vector512.LoadUnsafe(ref s, 576);
			x10 ^= Vector512.LoadUnsafe(ref s, 640);
			x11 ^= Vector512.LoadUnsafe(ref s, 704);
			x12 ^= Vector512.LoadUnsafe(ref s, 768);
			x13 ^= Vector512.LoadUnsafe(ref s, 832);
			x14 ^= Vector512.LoadUnsafe(ref s, 896);
			x15 ^= Vector512.LoadUnsafe(ref s, 960);

			x0.StoreUnsafe(ref dstRef, (nuint)(offset + 0));
			x1.StoreUnsafe(ref dstRef, (nuint)(offset + 64));
			x2.StoreUnsafe(ref dstRef, (nuint)(offset + 128));
			x3.StoreUnsafe(ref dstRef, (nuint)(offset + 192));
			x4.StoreUnsafe(ref dstRef, (nuint)(offset + 256));
			x5.StoreUnsafe(ref dstRef, (nuint)(offset + 320));
			x6.StoreUnsafe(ref dstRef, (nuint)(offset + 384));
			x7.StoreUnsafe(ref dstRef, (nuint)(offset + 448));
			x8.StoreUnsafe(ref dstRef, (nuint)(offset + 512));
			x9.StoreUnsafe(ref dstRef, (nuint)(offset + 576));
			x10.StoreUnsafe(ref dstRef, (nuint)(offset + 640));
			x11.StoreUnsafe(ref dstRef, (nuint)(offset + 704));
			x12.StoreUnsafe(ref dstRef, (nuint)(offset + 768));
			x13.StoreUnsafe(ref dstRef, (nuint)(offset + 832));
			x14.StoreUnsafe(ref dstRef, (nuint)(offset + 896));
			x15.StoreUnsafe(ref dstRef, (nuint)(offset + 960));

			counter += 16;
			offset += 1024;
			length -= 1024;
		}

		return offset;
	}

	[SkipLocalsInit]
	public static int SalsaCoreSoa2048Avx512(byte rounds, Span<uint> state, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int offset = 0;
		int length = source.Length;

		ref uint stateRef = ref state.GetReference();
		ref byte sourceRef = ref source.GetReference();
		ref byte dstRef = ref destination.GetReference();

		ref ulong counter = ref GetCounter(ref stateRef);

		Vector512<byte> o0 = Vector512.Create(Unsafe.Add(ref stateRef, 0)).AsByte();
		Vector512<byte> o1 = Vector512.Create(Unsafe.Add(ref stateRef, 1)).AsByte();
		Vector512<byte> o2 = Vector512.Create(Unsafe.Add(ref stateRef, 2)).AsByte();
		Vector512<byte> o3 = Vector512.Create(Unsafe.Add(ref stateRef, 3)).AsByte();
		Vector512<byte> o4 = Vector512.Create(Unsafe.Add(ref stateRef, 4)).AsByte();
		Vector512<byte> o5 = Vector512.Create(Unsafe.Add(ref stateRef, 5)).AsByte();
		Vector512<byte> o6 = Vector512.Create(Unsafe.Add(ref stateRef, 6)).AsByte();
		Vector512<byte> o7 = Vector512.Create(Unsafe.Add(ref stateRef, 7)).AsByte();
		// 8
		// 9
		Vector512<byte> o10 = Vector512.Create(Unsafe.Add(ref stateRef, 10)).AsByte();
		Vector512<byte> o11 = Vector512.Create(Unsafe.Add(ref stateRef, 11)).AsByte();
		Vector512<byte> o12 = Vector512.Create(Unsafe.Add(ref stateRef, 12)).AsByte();
		Vector512<byte> o13 = Vector512.Create(Unsafe.Add(ref stateRef, 13)).AsByte();
		Vector512<byte> o14 = Vector512.Create(Unsafe.Add(ref stateRef, 14)).AsByte();
		Vector512<byte> o15 = Vector512.Create(Unsafe.Add(ref stateRef, 15)).AsByte();

		while (length >= 2048)
		{
			ref byte s0 = ref Unsafe.Add(ref sourceRef, offset);
			ref byte s1 = ref Unsafe.Add(ref sourceRef, offset + 1024);

			ChaCha20Utils.AddAndTranspose(counter, out Vector512<byte> o8, out Vector512<byte> o9);
			Vector512<uint> t8 = o8.AsUInt32();
			Vector512<uint> t9 = o9.AsUInt32();
			Vector512<byte> x00 = o0;
			Vector512<byte> x01 = o1;
			Vector512<byte> x02 = o2;
			Vector512<byte> x03 = o3;
			Vector512<byte> x04 = o4;
			Vector512<byte> x05 = o5;
			Vector512<byte> x06 = o6;
			Vector512<byte> x07 = o7;
			Vector512<byte> x08 = o8;
			Vector512<byte> x09 = o9;
			Vector512<byte> x010 = o10;
			Vector512<byte> x011 = o11;
			Vector512<byte> x012 = o12;
			Vector512<byte> x013 = o13;
			Vector512<byte> x014 = o14;
			Vector512<byte> x015 = o15;

			ChaCha20Utils.AddAndTranspose(counter + 16, out o8, out o9);
			Vector512<byte> x10 = o0;
			Vector512<byte> x11 = o1;
			Vector512<byte> x12 = o2;
			Vector512<byte> x13 = o3;
			Vector512<byte> x14 = o4;
			Vector512<byte> x15 = o5;
			Vector512<byte> x16 = o6;
			Vector512<byte> x17 = o7;
			Vector512<byte> x18 = o8;
			Vector512<byte> x19 = o9;
			Vector512<byte> x110 = o10;
			Vector512<byte> x111 = o11;
			Vector512<byte> x112 = o12;
			Vector512<byte> x113 = o13;
			Vector512<byte> x114 = o14;
			Vector512<byte> x115 = o15;

			for (int i = 0; i < rounds; i += 2)
			{
				QuarterRound(ref x04, ref x00, ref x012, ref x08);
				QuarterRound(ref x09, ref x05, ref x01, ref x013);
				QuarterRound(ref x014, ref x010, ref x06, ref x02);
				QuarterRound(ref x03, ref x015, ref x011, ref x07);

				QuarterRound(ref x14, ref x10, ref x112, ref x18);
				QuarterRound(ref x19, ref x15, ref x11, ref x113);
				QuarterRound(ref x114, ref x110, ref x16, ref x12);
				QuarterRound(ref x13, ref x115, ref x111, ref x17);

				QuarterRound(ref x01, ref x00, ref x03, ref x02);
				QuarterRound(ref x06, ref x05, ref x04, ref x07);
				QuarterRound(ref x011, ref x010, ref x09, ref x08);
				QuarterRound(ref x012, ref x015, ref x014, ref x013);

				QuarterRound(ref x11, ref x10, ref x13, ref x12);
				QuarterRound(ref x16, ref x15, ref x14, ref x17);
				QuarterRound(ref x111, ref x110, ref x19, ref x18);
				QuarterRound(ref x112, ref x115, ref x114, ref x113);
			}

			x00 = (x00.AsUInt32() + o0.AsUInt32()).AsByte();
			x10 = (x10.AsUInt32() + o0.AsUInt32()).AsByte();
			x01 = (x01.AsUInt32() + o1.AsUInt32()).AsByte();
			x11 = (x11.AsUInt32() + o1.AsUInt32()).AsByte();
			x02 = (x02.AsUInt32() + o2.AsUInt32()).AsByte();
			x12 = (x12.AsUInt32() + o2.AsUInt32()).AsByte();
			x03 = (x03.AsUInt32() + o3.AsUInt32()).AsByte();
			x13 = (x13.AsUInt32() + o3.AsUInt32()).AsByte();
			x04 = (x04.AsUInt32() + o4.AsUInt32()).AsByte();
			x14 = (x14.AsUInt32() + o4.AsUInt32()).AsByte();
			x05 = (x05.AsUInt32() + o5.AsUInt32()).AsByte();
			x15 = (x15.AsUInt32() + o5.AsUInt32()).AsByte();
			x06 = (x06.AsUInt32() + o6.AsUInt32()).AsByte();
			x16 = (x16.AsUInt32() + o6.AsUInt32()).AsByte();
			x07 = (x07.AsUInt32() + o7.AsUInt32()).AsByte();
			x17 = (x17.AsUInt32() + o7.AsUInt32()).AsByte();
			x08 = (x08.AsUInt32() + t8).AsByte();
			x18 = (x18.AsUInt32() + o8.AsUInt32()).AsByte();
			x09 = (x09.AsUInt32() + t9).AsByte();
			x19 = (x19.AsUInt32() + o9.AsUInt32()).AsByte();
			x010 = (x010.AsUInt32() + o10.AsUInt32()).AsByte();
			x110 = (x110.AsUInt32() + o10.AsUInt32()).AsByte();
			x011 = (x011.AsUInt32() + o11.AsUInt32()).AsByte();
			x111 = (x111.AsUInt32() + o11.AsUInt32()).AsByte();
			x012 = (x012.AsUInt32() + o12.AsUInt32()).AsByte();
			x112 = (x112.AsUInt32() + o12.AsUInt32()).AsByte();
			x013 = (x013.AsUInt32() + o13.AsUInt32()).AsByte();
			x113 = (x113.AsUInt32() + o13.AsUInt32()).AsByte();
			x014 = (x014.AsUInt32() + o14.AsUInt32()).AsByte();
			x114 = (x114.AsUInt32() + o14.AsUInt32()).AsByte();
			x015 = (x015.AsUInt32() + o15.AsUInt32()).AsByte();
			x115 = (x115.AsUInt32() + o15.AsUInt32()).AsByte();

			VectorTranspose.Transpose(ref x00, ref x01, ref x02, ref x03, ref x04, ref x05, ref x06, ref x07, ref x08, ref x09, ref x010, ref x011, ref x012, ref x013, ref x014, ref x015);
			VectorTranspose.Transpose(ref x10, ref x11, ref x12, ref x13, ref x14, ref x15, ref x16, ref x17, ref x18, ref x19, ref x110, ref x111, ref x112, ref x113, ref x114, ref x115);

			x00 ^= Vector512.LoadUnsafe(ref s0, 0);
			x10 ^= Vector512.LoadUnsafe(ref s1, 0);
			x01 ^= Vector512.LoadUnsafe(ref s0, 64);
			x11 ^= Vector512.LoadUnsafe(ref s1, 64);
			x02 ^= Vector512.LoadUnsafe(ref s0, 128);
			x12 ^= Vector512.LoadUnsafe(ref s1, 128);
			x03 ^= Vector512.LoadUnsafe(ref s0, 192);
			x13 ^= Vector512.LoadUnsafe(ref s1, 192);
			x04 ^= Vector512.LoadUnsafe(ref s0, 256);
			x14 ^= Vector512.LoadUnsafe(ref s1, 256);
			x05 ^= Vector512.LoadUnsafe(ref s0, 320);
			x15 ^= Vector512.LoadUnsafe(ref s1, 320);
			x06 ^= Vector512.LoadUnsafe(ref s0, 384);
			x16 ^= Vector512.LoadUnsafe(ref s1, 384);
			x07 ^= Vector512.LoadUnsafe(ref s0, 448);
			x17 ^= Vector512.LoadUnsafe(ref s1, 448);
			x08 ^= Vector512.LoadUnsafe(ref s0, 512);
			x18 ^= Vector512.LoadUnsafe(ref s1, 512);
			x09 ^= Vector512.LoadUnsafe(ref s0, 576);
			x19 ^= Vector512.LoadUnsafe(ref s1, 576);
			x010 ^= Vector512.LoadUnsafe(ref s0, 640);
			x110 ^= Vector512.LoadUnsafe(ref s1, 640);
			x011 ^= Vector512.LoadUnsafe(ref s0, 704);
			x111 ^= Vector512.LoadUnsafe(ref s1, 704);
			x012 ^= Vector512.LoadUnsafe(ref s0, 768);
			x112 ^= Vector512.LoadUnsafe(ref s1, 768);
			x013 ^= Vector512.LoadUnsafe(ref s0, 832);
			x113 ^= Vector512.LoadUnsafe(ref s1, 832);
			x014 ^= Vector512.LoadUnsafe(ref s0, 896);
			x114 ^= Vector512.LoadUnsafe(ref s1, 896);
			x015 ^= Vector512.LoadUnsafe(ref s0, 960);
			x115 ^= Vector512.LoadUnsafe(ref s1, 960);

			x00.StoreUnsafe(ref dstRef, (nuint)(offset + 0));
			x01.StoreUnsafe(ref dstRef, (nuint)(offset + 64));
			x02.StoreUnsafe(ref dstRef, (nuint)(offset + 128));
			x03.StoreUnsafe(ref dstRef, (nuint)(offset + 192));
			x04.StoreUnsafe(ref dstRef, (nuint)(offset + 256));
			x05.StoreUnsafe(ref dstRef, (nuint)(offset + 320));
			x06.StoreUnsafe(ref dstRef, (nuint)(offset + 384));
			x07.StoreUnsafe(ref dstRef, (nuint)(offset + 448));
			x08.StoreUnsafe(ref dstRef, (nuint)(offset + 512));
			x09.StoreUnsafe(ref dstRef, (nuint)(offset + 576));
			x010.StoreUnsafe(ref dstRef, (nuint)(offset + 640));
			x011.StoreUnsafe(ref dstRef, (nuint)(offset + 704));
			x012.StoreUnsafe(ref dstRef, (nuint)(offset + 768));
			x013.StoreUnsafe(ref dstRef, (nuint)(offset + 832));
			x014.StoreUnsafe(ref dstRef, (nuint)(offset + 896));
			x015.StoreUnsafe(ref dstRef, (nuint)(offset + 960));
			x10.StoreUnsafe(ref dstRef, (nuint)(offset + 1024 + 0));
			x11.StoreUnsafe(ref dstRef, (nuint)(offset + 1024 + 64));
			x12.StoreUnsafe(ref dstRef, (nuint)(offset + 1024 + 128));
			x13.StoreUnsafe(ref dstRef, (nuint)(offset + 1024 + 192));
			x14.StoreUnsafe(ref dstRef, (nuint)(offset + 1024 + 256));
			x15.StoreUnsafe(ref dstRef, (nuint)(offset + 1024 + 320));
			x16.StoreUnsafe(ref dstRef, (nuint)(offset + 1024 + 384));
			x17.StoreUnsafe(ref dstRef, (nuint)(offset + 1024 + 448));
			x18.StoreUnsafe(ref dstRef, (nuint)(offset + 1024 + 512));
			x19.StoreUnsafe(ref dstRef, (nuint)(offset + 1024 + 576));
			x110.StoreUnsafe(ref dstRef, (nuint)(offset + 1024 + 640));
			x111.StoreUnsafe(ref dstRef, (nuint)(offset + 1024 + 704));
			x112.StoreUnsafe(ref dstRef, (nuint)(offset + 1024 + 768));
			x113.StoreUnsafe(ref dstRef, (nuint)(offset + 1024 + 832));
			x114.StoreUnsafe(ref dstRef, (nuint)(offset + 1024 + 896));
			x115.StoreUnsafe(ref dstRef, (nuint)(offset + 1024 + 960));

			counter += 32;
			offset += 2048;
			length -= 2048;
		}

		return offset;
	}
}
