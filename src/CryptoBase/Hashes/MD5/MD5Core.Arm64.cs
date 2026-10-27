namespace CryptoBase.Hashes.MD5;

public partial struct MD5Core
{
	private void ProcessBlocksArm64(ref byte source, int blockCount)
	{
		Debug.Assert(ArmBase.Arm64.IsSupported);
		ReadOnlySpan<uint> roundConstants = RoundConstants;
		uint stateA = _a;
		uint stateB = _b;
		uint stateC = _c;
		uint stateD = _d;

		do
		{
			ref InlineArray16<uint> x = ref Unsafe.As<byte, InlineArray16<uint>>(ref source);
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
			a = FF(a, b, c, d, x0, S11, roundConstants[0]);
			d = FF(d, a, b, c, x1, S12, roundConstants[1]);
			x2 = x[2];
			x3 = x[3];
			c = FF(c, d, a, b, x2, S13, roundConstants[2]);
			b = FF(b, c, d, a, x3, S14, roundConstants[3]);
			x4 = x[4];
			x5 = x[5];
			a = FF(a, b, c, d, x4, S11, roundConstants[4]);
			d = FF(d, a, b, c, x5, S12, roundConstants[5]);
			x6 = x[6];
			x7 = x[7];
			c = FF(c, d, a, b, x6, S13, roundConstants[6]);
			b = FF(b, c, d, a, x7, S14, roundConstants[7]);
			x8 = x[8];
			x9 = x[9];
			a = FF(a, b, c, d, x8, S11, roundConstants[8]);
			d = FF(d, a, b, c, x9, S12, roundConstants[9]);
			x10 = x[10];
			x11 = x[11];
			c = FF(c, d, a, b, x10, S13, roundConstants[10]);
			b = FF(b, c, d, a, x11, S14, roundConstants[11]);
			x12 = x[12];
			x13 = x[13];
			a = FF(a, b, c, d, x12, S11, roundConstants[12]);
			d = FF(d, a, b, c, x13, S12, roundConstants[13]);
			x14 = x[14];
			x15 = x[15];
			c = FF(c, d, a, b, x14, S13, roundConstants[14]);
			b = FF(b, c, d, a, x15, S14, roundConstants[15]);

			a = GG(a, b, c, d, x1, S21, roundConstants[16]);
			d = GG(d, a, b, c, x6, S22, roundConstants[17]);
			c = GG(c, d, a, b, x11, S23, roundConstants[18]);
			b = GG(b, c, d, a, x0, S24, roundConstants[19]);
			a = GG(a, b, c, d, x5, S21, roundConstants[20]);
			d = GG(d, a, b, c, x10, S22, roundConstants[21]);
			c = GG(c, d, a, b, x15, S23, roundConstants[22]);
			b = GG(b, c, d, a, x4, S24, roundConstants[23]);
			a = GG(a, b, c, d, x9, S21, roundConstants[24]);
			d = GG(d, a, b, c, x14, S22, roundConstants[25]);
			c = GG(c, d, a, b, x3, S23, roundConstants[26]);
			b = GG(b, c, d, a, x8, S24, roundConstants[27]);
			a = GG(a, b, c, d, x13, S21, roundConstants[28]);
			d = GG(d, a, b, c, x2, S22, roundConstants[29]);
			c = GG(c, d, a, b, x7, S23, roundConstants[30]);
			b = GG(b, c, d, a, x12, S24, roundConstants[31]);

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

			a = II(a, b, c, d, x0, S41, roundConstants[48]);
			d = II(d, a, b, c, x7, S42, roundConstants[49]);
			c = II(c, d, a, b, x14, S43, roundConstants[50]);
			b = II(b, c, d, a, x5, S44, roundConstants[51]);
			a = II(a, b, c, d, x12, S41, roundConstants[52]);
			d = II(d, a, b, c, x3, S42, roundConstants[53]);
			c = II(c, d, a, b, x10, S43, roundConstants[54]);
			b = II(b, c, d, a, x1, S44, roundConstants[55]);
			a = II(a, b, c, d, x8, S41, roundConstants[56]);
			d = II(d, a, b, c, x15, S42, roundConstants[57]);
			c = II(c, d, a, b, x6, S43, roundConstants[58]);
			b = II(b, c, d, a, x13, S44, roundConstants[59]);
			a = II(a, b, c, d, x4, S41, roundConstants[60]);
			d = II(d, a, b, c, x11, S42, roundConstants[61]);
			c = II(c, d, a, b, x2, S43, roundConstants[62]);
			b = II(b, c, d, a, x9, S44, roundConstants[63]);

			stateA += a;
			stateB += b;
			stateC += c;
			stateD += d;

			source = ref Unsafe.Add(ref source, BlockSizeInBytes);
		} while (--blockCount is not 0);

		_a = stateA;
		_b = stateB;
		_c = stateC;
		_d = stateD;
	}
}
