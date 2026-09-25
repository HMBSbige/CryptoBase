namespace CryptoBase.Ciphers.Blocks.SM4;

internal static class SM4Scalar
{
	internal static uint SubByte(uint value)
	{
		uint bit1 = value >> 1;
		uint bit2 = value >> 2;
		uint bit3 = value >> 3;
		uint bit4 = value >> 4;
		uint bit5 = value >> 5;
		uint bit6 = value >> 6;
		uint bit7 = value >> 7;

		uint xor26 = bit2 ^ bit6;
		uint xor34 = bit3 ^ bit4;
		uint xor27 = bit2 ^ bit7;
		uint xor267 = bit7 ^ xor26;
		uint xor127 = bit1 ^ xor27;
		uint xor67 = bit6 ^ bit7;
		uint xor026 = value ^ xor26;
		uint xor126 = bit1 ^ xor26;
		uint affine0 = ~(bit5 ^ xor126);
		uint affine1 = xor34 ^ xor127;
		uint affine2 = value ^ xor34;
		uint affine4 = value ^ xor127;
		uint affine3 = bit3 ^ affine4;
		uint affine5 = bit5 ^ xor026;
		uint affine6 = ~(value ^ bit1);
		uint affine7 = ~(xor34 ^ xor126);
		uint affine8 = xor34 ^ xor026;
		uint affine11 = xor34 ^ xor67;
		uint affine12 = bit5 ^ xor67;
		uint affine13 = ~(bit5 ^ affine1);
		uint affine14 = ~(bit4 ^ xor267);
		uint affine15 = ~(bit1 ^ bit3 ^ bit6);
		uint affine16 = ~(value ^ xor267);
		uint affine17 = ~(xor34 ^ xor267);
		uint affine20 = value ^ xor27;

		uint sharedProduct0 = bit3 & affine5;
		uint sharedProduct1 = affine1 & affine11;
		uint productMix0 = affine4 & affine20 ^ sharedProduct1;
		uint productMix1 = affine2 & affine8 ^ sharedProduct1;
		uint state0 = xor126 ^ sharedProduct0 ^ affine17 & affine6 ^ productMix0;
		uint state1 = affine14 & affine0 ^ sharedProduct0 ^ xor26 ^ productMix1;
		uint state2 = (affine3 | affine12) ^ affine16 & affine7 ^ productMix0;
		uint state3 = affine15 & affine13 ^ affine3 & affine12 ^ productMix1 ^ ~(bit5 ^ affine14);

		uint leftMix = state0 ^ state1;
		uint rightMix = state2 ^ state3;
		uint crossProduct = state0 & state2;
		uint savedState1 = state1;
		state0 = crossProduct ^ leftMix & ~(state0 & state3);
		state1 ^= (state3 ^ crossProduct) & leftMix;
		state3 ^= (savedState1 ^ crossProduct) & rightMix;
		state2 = crossProduct ^ rightMix & ~(savedState1 & state2);

		uint pair02 = state0 ^ state2;
		uint pair13 = state1 ^ state3;
		uint pair01 = state0 ^ state1;
		uint pair23 = state2 ^ state3;
		uint product0 = state0 & affine7;
		uint product1 = state1 & affine13;
		uint product2 = pair13 & affine11;
		uint product3 = (pair02 ^ pair13) & affine20;
		uint product4 = pair02 & affine8;
		uint product5 = pair23 & bit3;
		uint product6 = state2 & affine17;
		uint product7 = state3 & affine14;
		uint product8 = pair01 & affine3;
		uint product9 = state0 & affine16;
		uint product10 = state1 & affine15;
		uint product11 = pair13 & affine1;
		uint product12 = (pair02 ^ pair13) & affine4;
		uint product13 = pair02 & affine2;
		uint product14 = pair23 & affine5;
		uint product15 = state2 & affine6;
		uint product16 = state3 & affine0;
		uint product17 = pair01 & affine12;

		uint outputMix0 = product4 ^ product7;
		uint outputMix1 = product13 ^ product15;
		uint outputMix2 = product2 ^ product16;
		uint outputMix3 = product6 ^ outputMix0;
		uint outputMix4 = product12 ^ outputMix1;
		uint outputMix5 = product9 ^ product10;
		uint outputMix6 = product11 ^ outputMix2;
		uint outputMix7 = product1 ^ outputMix4;
		uint outputMix8 = product0 ^ product17;
		uint outputMix10 = product8 ^ outputMix3;
		uint outputMix11 = outputMix2 ^ outputMix5;
		uint outputMix12 = product14 ^ outputMix6;
		uint outputMix13 = outputMix7 ^ product3 ^ product17;
		uint outputBit0 = ~(outputMix11 ^ outputMix13);
		uint outputBit1 = ~(product7 ^ product16 ^ outputMix7 ^ product0 ^ product6);
		uint outputBit2 = product4 ^ outputMix4 ^ outputMix8 ^ outputMix11;
		uint outputBit3 = product5 ^ product13 ^ outputMix0 ^ outputMix12;
		uint outputBit4 = ~(product3 ^ product15 ^ outputMix3 ^ product16 ^ outputMix5);
		uint outputBit5 = product14 ^ outputMix3 ^ outputMix13;
		uint outputBit6 = ~(product10 ^ product12 ^ outputMix10 ^ outputMix12);
		uint outputBit7 = ~(product9 ^ outputMix1 ^ outputMix6 ^ outputMix8 ^ outputMix10);

		const uint laneMask = 0x01010101;
		return outputBit0 & laneMask
				| (outputBit1 & laneMask) << 1
				| (outputBit2 & laneMask) << 2
				| (outputBit3 & laneMask) << 3
				| (outputBit4 & laneMask) << 4
				| (outputBit5 & laneMask) << 5
				| (outputBit6 & laneMask) << 6
				| (outputBit7 & laneMask) << 7;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint T(uint b)
	{
		b = SubByte(b);
		return b ^ b.RotateLeft(2) ^ b.RotateLeft(10) ^ b.RotateLeft(18) ^ b.RotateLeft(24);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static void ProcessBlock(ReadOnlySpan<uint> rk, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		uint x0 = BinaryPrimitives.ReadUInt32BigEndian(source);
		uint x1 = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(4));
		uint x2 = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(8));
		uint x3 = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(12));
		ref uint keys = ref rk.GetReference();

		for (int i = 0; i < 32; i += 4)
		{
			x0 ^= T(x1 ^ x2 ^ x3 ^ Unsafe.Add(ref keys, i));
			x1 ^= T(x0 ^ x2 ^ x3 ^ Unsafe.Add(ref keys, i + 1));
			x2 ^= T(x0 ^ x1 ^ x3 ^ Unsafe.Add(ref keys, i + 2));
			x3 ^= T(x0 ^ x1 ^ x2 ^ Unsafe.Add(ref keys, i + 3));
		}

		BinaryPrimitives.WriteUInt32BigEndian(destination, x3);
		BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(4), x2);
		BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(8), x1);
		BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(12), x0);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	internal static void ProcessBlocks(ref uint rk, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ReadOnlySpan<uint> keys = MemoryMarshal.CreateReadOnlySpan(ref rk, 32);

		for (int offset = 0; offset < source.Length; offset += 16)
		{
			ProcessBlock(keys, source.Slice(offset, 16), destination.Slice(offset, 16));
		}
	}
}
