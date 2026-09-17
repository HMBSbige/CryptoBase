namespace CryptoBase.Ciphers.Streams;

internal static partial class ChaCha20Utils
{
	private static int XorNeon(ref uint stateRef, ref byte input, ref byte output, int length)
	{
		ref ulong counter = ref GetCounterOriginal(ref stateRef);
		int processed = 0;
		Vector128<uint> s0 = Vector128.LoadUnsafe(ref stateRef, 0);
		Vector128<uint> s1 = Vector128.LoadUnsafe(ref stateRef, 4);
		Vector128<uint> s2 = Vector128.LoadUnsafe(ref stateRef, 8);
		Vector128<uint> s3 = Vector128.LoadUnsafe(ref stateRef, 12);

		while (length - processed >= 512)
		{
			Vector128<uint> a0 = s0;
			Vector128<uint> a1 = s1;
			Vector128<uint> a2 = s2;
			Vector128<uint> a3 = s3.WithElement(0, (uint)counter);
			Vector128<uint> b0 = s0;
			Vector128<uint> b1 = s1;
			Vector128<uint> b2 = s2;
			Vector128<uint> b3 = s3.WithElement(0, (uint)(counter + 1));
			Vector128<uint> c0 = s0;
			Vector128<uint> c1 = s1;
			Vector128<uint> c2 = s2;
			Vector128<uint> c3 = s3.WithElement(0, (uint)(counter + 2));
			Vector128<uint> d0 = s0;
			Vector128<uint> d1 = s1;
			Vector128<uint> d2 = s2;
			Vector128<uint> d3 = s3.WithElement(0, (uint)(counter + 3));
			Vector128<uint> e0 = s0;
			Vector128<uint> e1 = s1;
			Vector128<uint> e2 = s2;
			Vector128<uint> e3 = s3.WithElement(0, (uint)(counter + 4));
			Vector128<uint> f0 = s0;
			Vector128<uint> f1 = s1;
			Vector128<uint> f2 = s2;
			Vector128<uint> f3 = s3.WithElement(0, (uint)(counter + 5));

			for (int half = 0; half < 2; ++half)
			{
				uint initialCounter = (uint)counter + 6 + (uint)half;
				uint x00 = Unsafe.Add(ref stateRef, 0);
				uint x01 = Unsafe.Add(ref stateRef, 1);
				uint x02 = Unsafe.Add(ref stateRef, 2);
				uint x03 = Unsafe.Add(ref stateRef, 3);
				uint x04 = Unsafe.Add(ref stateRef, 4);
				uint x05 = Unsafe.Add(ref stateRef, 5);
				uint x06 = Unsafe.Add(ref stateRef, 6);
				uint x07 = Unsafe.Add(ref stateRef, 7);
				uint x08 = Unsafe.Add(ref stateRef, 8);
				uint x09 = Unsafe.Add(ref stateRef, 9);
				uint x10 = Unsafe.Add(ref stateRef, 10);
				uint x11 = Unsafe.Add(ref stateRef, 11);
				uint x12 = initialCounter;
				uint x13 = Unsafe.Add(ref stateRef, 13);
				uint x14 = Unsafe.Add(ref stateRef, 14);
				uint x15 = Unsafe.Add(ref stateRef, 15);

				// Complete six NEON blocks across both halves, interleaving one scalar block per half.
				// Each inner iteration advances the NEON blocks by one round and the scalar block by one double-round.
				for (int round = 0; round < SnuffleCipher.Rounds / 2; ++round)
				{
					a0 += a1;
					x00 += x04;
					b0 += b1;
					x01 += x05;
					c0 += c1;
					x02 += x06;
					d0 += d1;
					x03 += x07;
					e0 += e1;
					x12 = (x12 ^ x00).RotateLeft(16);
					f0 += f1;
					x13 = (x13 ^ x01).RotateLeft(16);
					a3 = (a3 ^ a0).RotateLeftUInt32(16);
					x14 = (x14 ^ x02).RotateLeft(16);
					b3 = (b3 ^ b0).RotateLeftUInt32(16);
					x15 = (x15 ^ x03).RotateLeft(16);
					c3 = (c3 ^ c0).RotateLeftUInt32(16);
					x08 += x12;
					d3 = (d3 ^ d0).RotateLeftUInt32(16);
					x09 += x13;
					e3 = (e3 ^ e0).RotateLeftUInt32(16);
					x10 += x14;
					f3 = (f3 ^ f0).RotateLeftUInt32(16);
					x11 += x15;
					a2 += a3;
					x04 = (x04 ^ x08).RotateLeft(12);
					b2 += b3;
					x05 = (x05 ^ x09).RotateLeft(12);
					c2 += c3;
					x06 = (x06 ^ x10).RotateLeft(12);
					d2 += d3;
					x07 = (x07 ^ x11).RotateLeft(12);
					e2 += e3;
					x00 += x04;
					f2 += f3;
					x01 += x05;
					a1 = (a1 ^ a2).RotateLeftUInt32(12);
					x02 += x06;
					b1 = (b1 ^ b2).RotateLeftUInt32(12);
					x03 += x07;
					c1 = (c1 ^ c2).RotateLeftUInt32(12);
					x12 = (x12 ^ x00).RotateLeft(8);
					d1 = (d1 ^ d2).RotateLeftUInt32(12);
					x13 = (x13 ^ x01).RotateLeft(8);
					e1 = (e1 ^ e2).RotateLeftUInt32(12);
					x14 = (x14 ^ x02).RotateLeft(8);
					f1 = (f1 ^ f2).RotateLeftUInt32(12);
					x15 = (x15 ^ x03).RotateLeft(8);
					a0 += a1;
					x08 += x12;
					b0 += b1;
					x09 += x13;
					c0 += c1;
					x10 += x14;
					d0 += d1;
					x11 += x15;
					e0 += e1;
					x04 = (x04 ^ x08).RotateLeft(7);
					f0 += f1;
					x05 = (x05 ^ x09).RotateLeft(7);
					a3 = (a3 ^ a0).RotateLeftUInt32(8);
					x06 = (x06 ^ x10).RotateLeft(7);
					b3 = (b3 ^ b0).RotateLeftUInt32(8);
					x07 = (x07 ^ x11).RotateLeft(7);
					c3 = (c3 ^ c0).RotateLeftUInt32(8);
					x00 += x05;
					d3 = (d3 ^ d0).RotateLeftUInt32(8);
					x01 += x06;
					e3 = (e3 ^ e0).RotateLeftUInt32(8);
					x02 += x07;
					f3 = (f3 ^ f0).RotateLeftUInt32(8);
					x03 += x04;
					a2 += a3;
					x15 = (x15 ^ x00).RotateLeft(16);
					b2 += b3;
					x12 = (x12 ^ x01).RotateLeft(16);
					c2 += c3;
					x13 = (x13 ^ x02).RotateLeft(16);
					d2 += d3;
					x14 = (x14 ^ x03).RotateLeft(16);
					e2 += e3;
					x10 += x15;
					f2 += f3;
					x11 += x12;
					a1 = (a1 ^ a2).RotateLeftUInt32(7);
					x08 += x13;
					b1 = (b1 ^ b2).RotateLeftUInt32(7);
					x09 += x14;
					c1 = (c1 ^ c2).RotateLeftUInt32(7);
					x05 = (x05 ^ x10).RotateLeft(12);
					d1 = (d1 ^ d2).RotateLeftUInt32(7);
					x06 = (x06 ^ x11).RotateLeft(12);
					e1 = (e1 ^ e2).RotateLeftUInt32(7);
					x07 = (x07 ^ x08).RotateLeft(12);
					f1 = (f1 ^ f2).RotateLeftUInt32(7);
					x04 = (x04 ^ x09).RotateLeft(12);
					x00 += x05;
					x01 += x06;
					x02 += x07;
					x03 += x04;
					x15 = (x15 ^ x00).RotateLeft(8);
					x12 = (x12 ^ x01).RotateLeft(8);
					x13 = (x13 ^ x02).RotateLeft(8);
					x14 = (x14 ^ x03).RotateLeft(8);
					x10 += x15;
					x11 += x12;
					x08 += x13;
					x09 += x14;
					x05 = (x05 ^ x10).RotateLeft(7);
					x06 = (x06 ^ x11).RotateLeft(7);
					x07 = (x07 ^ x08).RotateLeft(7);
					x04 = (x04 ^ x09).RotateLeft(7);

					if ((round & 1) == 0)
					{
						a0 = a0.RotateWordsLeft(3);
						a2 = a2.RotateWordsLeft(1);
						a3 = a3.RotateWordsLeft(2);
						b0 = b0.RotateWordsLeft(3);
						b2 = b2.RotateWordsLeft(1);
						b3 = b3.RotateWordsLeft(2);
						c0 = c0.RotateWordsLeft(3);
						c2 = c2.RotateWordsLeft(1);
						c3 = c3.RotateWordsLeft(2);
						d0 = d0.RotateWordsLeft(3);
						d2 = d2.RotateWordsLeft(1);
						d3 = d3.RotateWordsLeft(2);
						e0 = e0.RotateWordsLeft(3);
						e2 = e2.RotateWordsLeft(1);
						e3 = e3.RotateWordsLeft(2);
						f0 = f0.RotateWordsLeft(3);
						f2 = f2.RotateWordsLeft(1);
						f3 = f3.RotateWordsLeft(2);
					}
					else
					{
						a0 = a0.RotateWordsLeft(1);
						a2 = a2.RotateWordsLeft(3);
						a3 = a3.RotateWordsLeft(2);
						b0 = b0.RotateWordsLeft(1);
						b2 = b2.RotateWordsLeft(3);
						b3 = b3.RotateWordsLeft(2);
						c0 = c0.RotateWordsLeft(1);
						c2 = c2.RotateWordsLeft(3);
						c3 = c3.RotateWordsLeft(2);
						d0 = d0.RotateWordsLeft(1);
						d2 = d2.RotateWordsLeft(3);
						d3 = d3.RotateWordsLeft(2);
						e0 = e0.RotateWordsLeft(1);
						e2 = e2.RotateWordsLeft(3);
						e3 = e3.RotateWordsLeft(2);
						f0 = f0.RotateWordsLeft(1);
						f2 = f2.RotateWordsLeft(3);
						f3 = f3.RotateWordsLeft(2);
					}
				}

				ref byte scalarInput = ref Unsafe.Add(ref input, processed + 384 + half * 64);
				ref byte scalarOutput = ref Unsafe.Add(ref output, processed + 384 + half * 64);
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref scalarOutput, 0), x00 + Unsafe.Add(ref stateRef, 0) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref scalarInput, 0)));
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref scalarOutput, 4), x01 + Unsafe.Add(ref stateRef, 1) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref scalarInput, 4)));
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref scalarOutput, 8), x02 + Unsafe.Add(ref stateRef, 2) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref scalarInput, 8)));
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref scalarOutput, 12), x03 + Unsafe.Add(ref stateRef, 3) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref scalarInput, 12)));
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref scalarOutput, 16), x04 + Unsafe.Add(ref stateRef, 4) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref scalarInput, 16)));
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref scalarOutput, 20), x05 + Unsafe.Add(ref stateRef, 5) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref scalarInput, 20)));
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref scalarOutput, 24), x06 + Unsafe.Add(ref stateRef, 6) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref scalarInput, 24)));
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref scalarOutput, 28), x07 + Unsafe.Add(ref stateRef, 7) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref scalarInput, 28)));
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref scalarOutput, 32), x08 + Unsafe.Add(ref stateRef, 8) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref scalarInput, 32)));
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref scalarOutput, 36), x09 + Unsafe.Add(ref stateRef, 9) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref scalarInput, 36)));
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref scalarOutput, 40), x10 + Unsafe.Add(ref stateRef, 10) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref scalarInput, 40)));
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref scalarOutput, 44), x11 + Unsafe.Add(ref stateRef, 11) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref scalarInput, 44)));
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref scalarOutput, 48), x12 + initialCounter ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref scalarInput, 48)));
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref scalarOutput, 52), x13 + Unsafe.Add(ref stateRef, 13) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref scalarInput, 52)));
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref scalarOutput, 56), x14 + Unsafe.Add(ref stateRef, 14) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref scalarInput, 56)));
				Unsafe.WriteUnaligned(ref Unsafe.Add(ref scalarOutput, 60), x15 + Unsafe.Add(ref stateRef, 15) ^ Unsafe.ReadUnaligned<uint>(ref Unsafe.Add(ref scalarInput, 60)));
			}

			a0 += s0;
			(a0.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)processed)).StoreUnsafe(ref output, (nuint)processed);
			a1 += s1;
			(a1.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 16))).StoreUnsafe(ref output, (nuint)(processed + 16));
			a2 += s2;
			(a2.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 32))).StoreUnsafe(ref output, (nuint)(processed + 32));
			a3 += s3.WithElement(0, (uint)counter);
			(a3.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 48))).StoreUnsafe(ref output, (nuint)(processed + 48));
			b0 += s0;
			(b0.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 64))).StoreUnsafe(ref output, (nuint)(processed + 64));
			b1 += s1;
			(b1.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 80))).StoreUnsafe(ref output, (nuint)(processed + 80));
			b2 += s2;
			(b2.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 96))).StoreUnsafe(ref output, (nuint)(processed + 96));
			b3 += s3.WithElement(0, (uint)(counter + 1));
			(b3.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 112))).StoreUnsafe(ref output, (nuint)(processed + 112));
			c0 += s0;
			(c0.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 128))).StoreUnsafe(ref output, (nuint)(processed + 128));
			c1 += s1;
			(c1.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 144))).StoreUnsafe(ref output, (nuint)(processed + 144));
			c2 += s2;
			(c2.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 160))).StoreUnsafe(ref output, (nuint)(processed + 160));
			c3 += s3.WithElement(0, (uint)(counter + 2));
			(c3.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 176))).StoreUnsafe(ref output, (nuint)(processed + 176));
			d0 += s0;
			(d0.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 192))).StoreUnsafe(ref output, (nuint)(processed + 192));
			d1 += s1;
			(d1.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 208))).StoreUnsafe(ref output, (nuint)(processed + 208));
			d2 += s2;
			(d2.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 224))).StoreUnsafe(ref output, (nuint)(processed + 224));
			d3 += s3.WithElement(0, (uint)(counter + 3));
			(d3.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 240))).StoreUnsafe(ref output, (nuint)(processed + 240));
			e0 += s0;
			(e0.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 256))).StoreUnsafe(ref output, (nuint)(processed + 256));
			e1 += s1;
			(e1.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 272))).StoreUnsafe(ref output, (nuint)(processed + 272));
			e2 += s2;
			(e2.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 288))).StoreUnsafe(ref output, (nuint)(processed + 288));
			e3 += s3.WithElement(0, (uint)(counter + 4));
			(e3.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 304))).StoreUnsafe(ref output, (nuint)(processed + 304));
			f0 += s0;
			(f0.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 320))).StoreUnsafe(ref output, (nuint)(processed + 320));
			f1 += s1;
			(f1.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 336))).StoreUnsafe(ref output, (nuint)(processed + 336));
			f2 += s2;
			(f2.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 352))).StoreUnsafe(ref output, (nuint)(processed + 352));
			f3 += s3.WithElement(0, (uint)(counter + 5));
			(f3.AsByte() ^ Vector128.LoadUnsafe(ref input, (nuint)(processed + 368))).StoreUnsafe(ref output, (nuint)(processed + 368));
			counter += 8;
			processed += 512;
		}

		return processed;
	}
}
