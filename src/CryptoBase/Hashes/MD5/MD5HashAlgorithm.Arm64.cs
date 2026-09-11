namespace CryptoBase.Hashes.MD5;

public partial struct MD5HashAlgorithm
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint FFArm64(uint a, uint b, uint c, uint d, uint mj, int s, uint ti)
	{
		uint selected = c ^ d;
		a += mj + ti;
		selected &= b;
		selected ^= d;
		a += selected;
		return a.RotateLeft(s) + b;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint GGArm64(uint a, uint b, uint c, uint d, uint mj, int s, uint ti)
	{
		a += mj + ti;
		a += c & ~d;
		a += b & d;
		return a.RotateLeft(s) + b;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint IIArm64(uint a, uint b, uint c, uint d, uint mj, int s, uint ti)
	{
		uint selected = ~d;
		a += mj + ti;
		selected |= b;
		selected ^= c;
		a += selected;
		return a.RotateLeft(s) + b;
	}

	private static void ProcessBlocksArm64(ref MD5HashAlgorithm hashAlgorithm, ref byte source, int blockCount)
	{
		Debug.Assert(ArmBase.Arm64.IsSupported);
		ReadOnlySpan<uint> roundConstants = RoundConstants;
		uint stateA = hashAlgorithm._a;
		uint stateB = hashAlgorithm._b;
		uint stateC = hashAlgorithm._c;
		uint stateD = hashAlgorithm._d;

		do
		{
			ref InlineArray16<uint> x = ref source.As<InlineArray16<uint>>();
			uint x0;
			uint x1;
			uint x2;
			uint x3;
			uint x4;
			uint x5;
			uint x6;
			uint x7;
			uint x8;
			uint x9;
			uint x10;
			uint x11;
			uint x12;
			uint x13;
			uint x14;
			uint x15;
			uint a = stateA;
			uint b = stateB;
			uint c = stateC;
			uint d = stateD;

			x0 = x[0];
			x1 = x[1];
			a = FFArm64(a, b, c, d, x0, S11, roundConstants[0]);
			d = FFArm64(d, a, b, c, x1, S12, roundConstants[1]);
			x2 = x[2];
			x3 = x[3];
			c = FFArm64(c, d, a, b, x2, S13, roundConstants[2]);
			b = FFArm64(b, c, d, a, x3, S14, roundConstants[3]);
			x4 = x[4];
			x5 = x[5];
			a = FFArm64(a, b, c, d, x4, S11, roundConstants[4]);
			d = FFArm64(d, a, b, c, x5, S12, roundConstants[5]);
			x6 = x[6];
			x7 = x[7];
			c = FFArm64(c, d, a, b, x6, S13, roundConstants[6]);
			b = FFArm64(b, c, d, a, x7, S14, roundConstants[7]);
			x8 = x[8];
			x9 = x[9];
			a = FFArm64(a, b, c, d, x8, S11, roundConstants[8]);
			d = FFArm64(d, a, b, c, x9, S12, roundConstants[9]);
			x10 = x[10];
			x11 = x[11];
			c = FFArm64(c, d, a, b, x10, S13, roundConstants[10]);
			b = FFArm64(b, c, d, a, x11, S14, roundConstants[11]);
			x12 = x[12];
			x13 = x[13];
			a = FFArm64(a, b, c, d, x12, S11, roundConstants[12]);
			d = FFArm64(d, a, b, c, x13, S12, roundConstants[13]);
			x14 = x[14];
			x15 = x[15];
			c = FFArm64(c, d, a, b, x14, S13, roundConstants[14]);
			b = FFArm64(b, c, d, a, x15, S14, roundConstants[15]);

			a = GGArm64(a, b, c, d, x1, S21, roundConstants[16]);
			d = GGArm64(d, a, b, c, x6, S22, roundConstants[17]);
			c = GGArm64(c, d, a, b, x11, S23, roundConstants[18]);
			b = GGArm64(b, c, d, a, x0, S24, roundConstants[19]);
			a = GGArm64(a, b, c, d, x5, S21, roundConstants[20]);
			d = GGArm64(d, a, b, c, x10, S22, roundConstants[21]);
			c = GGArm64(c, d, a, b, x15, S23, roundConstants[22]);
			b = GGArm64(b, c, d, a, x4, S24, roundConstants[23]);
			a = GGArm64(a, b, c, d, x9, S21, roundConstants[24]);
			d = GGArm64(d, a, b, c, x14, S22, roundConstants[25]);
			c = GGArm64(c, d, a, b, x3, S23, roundConstants[26]);
			b = GGArm64(b, c, d, a, x8, S24, roundConstants[27]);
			a = GGArm64(a, b, c, d, x13, S21, roundConstants[28]);
			d = GGArm64(d, a, b, c, x2, S22, roundConstants[29]);
			c = GGArm64(c, d, a, b, x7, S23, roundConstants[30]);
			b = GGArm64(b, c, d, a, x12, S24, roundConstants[31]);

			a = HH(a, b, c, d, x5, S31, roundConstants[32]);
			d = HH(d, a, b, c, x8, S32, roundConstants[33]);
			c = HH(c, d, a, b, x11, S33, roundConstants[34]);
			b = HH(b, c, d, a, x14, S34, roundConstants[35]);
			a = HH(a, b, c, d, x1, S31, roundConstants[36]);
			d = HH(d, a, b, c, x4, S32, roundConstants[37]);
			c = HH(c, d, a, b, x7, S33, roundConstants[38]);
			b = HH(b, c, d, a, x10, S34, roundConstants[39]);
			a = HH(a, b, c, d, x13, S31, roundConstants[40]);
			d = HH(d, a, b, c, x0, S32, roundConstants[41]);
			c = HH(c, d, a, b, x3, S33, roundConstants[42]);
			b = HH(b, c, d, a, x6, S34, roundConstants[43]);
			a = HH(a, b, c, d, x9, S31, roundConstants[44]);
			d = HH(d, a, b, c, x12, S32, roundConstants[45]);
			c = HH(c, d, a, b, x15, S33, roundConstants[46]);
			b = HH(b, c, d, a, x2, S34, roundConstants[47]);

			a = IIArm64(a, b, c, d, x0, S41, roundConstants[48]);
			d = IIArm64(d, a, b, c, x7, S42, roundConstants[49]);
			c = IIArm64(c, d, a, b, x14, S43, roundConstants[50]);
			b = IIArm64(b, c, d, a, x5, S44, roundConstants[51]);
			a = IIArm64(a, b, c, d, x12, S41, roundConstants[52]);
			d = IIArm64(d, a, b, c, x3, S42, roundConstants[53]);
			c = IIArm64(c, d, a, b, x10, S43, roundConstants[54]);
			b = IIArm64(b, c, d, a, x1, S44, roundConstants[55]);
			a = IIArm64(a, b, c, d, x8, S41, roundConstants[56]);
			d = IIArm64(d, a, b, c, x15, S42, roundConstants[57]);
			c = IIArm64(c, d, a, b, x6, S43, roundConstants[58]);
			b = IIArm64(b, c, d, a, x13, S44, roundConstants[59]);
			a = IIArm64(a, b, c, d, x4, S41, roundConstants[60]);
			d = IIArm64(d, a, b, c, x11, S42, roundConstants[61]);
			c = IIArm64(c, d, a, b, x2, S43, roundConstants[62]);
			b = IIArm64(b, c, d, a, x9, S44, roundConstants[63]);

			stateA += a;
			stateB += b;
			stateC += c;
			stateD += d;

			source = ref Unsafe.Add(ref source, BlockSizeInBytes);
		} while (--blockCount is not 0);

		hashAlgorithm._a = stateA;
		hashAlgorithm._b = stateB;
		hashAlgorithm._c = stateC;
		hashAlgorithm._d = stateD;
	}
}
