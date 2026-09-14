using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Hashes.MD5;

public partial struct MD5HashAlgorithm
{
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static uint ReadX64Message(ref byte source, int wordIndex)
	{
		// Keep repeated words as source loads instead of JIT common subexpressions that spill to the stack.
		return Volatile.Read(ref Unsafe.Add(ref source, wordIndex * sizeof(uint)).As<uint>());
	}

	[SuppressMessage("ReSharper", "RedundantAssignment")]
	private static void ProcessBlocksX64(ref MD5HashAlgorithm hashAlgorithm, ref byte source, int blockCount)
	{
		Debug.Assert(X86Base.X64.IsSupported);
		uint stateA = hashAlgorithm._a;
		uint stateB = hashAlgorithm._b;
		uint stateC = hashAlgorithm._c;
		uint stateD = hashAlgorithm._d;

		do
		{
			uint a = stateA;
			uint b = stateB;
			uint c = stateC;
			uint d = stateD;
			uint message = ReadX64Message(ref source, 0);
			uint selected = d;
			uint selected2;

			// Round 1.
			selected ^= c;
			a += message + 0xD76AA478U;
			selected &= b;
			message = ReadX64Message(ref source, 1);
			selected ^= d;
			a += selected;
			a = a.RotateLeft(7);
			selected = c;
			a += b;

			selected ^= b;
			d += message + 0xE8C7B756U;
			selected &= a;
			message = ReadX64Message(ref source, 2);
			selected ^= c;
			d += selected;
			d = d.RotateLeft(12);
			selected = b;
			d += a;

			selected ^= a;
			c += message + 0x242070DBU;
			selected &= d;
			message = ReadX64Message(ref source, 3);
			selected ^= b;
			c += selected;
			c = c.RotateLeft(17);
			selected = a;
			c += d;

			selected ^= d;
			b += message + 0xC1BDCEEEU;
			selected &= c;
			message = ReadX64Message(ref source, 4);
			selected ^= a;
			b += selected;
			b = b.RotateLeft(22);
			selected = d;
			b += c;

			selected ^= c;
			a += message + 0xF57C0FAFU;
			selected &= b;
			message = ReadX64Message(ref source, 5);
			selected ^= d;
			a += selected;
			a = a.RotateLeft(7);
			selected = c;
			a += b;

			selected ^= b;
			d += message + 0x4787C62AU;
			selected &= a;
			message = ReadX64Message(ref source, 6);
			selected ^= c;
			d += selected;
			d = d.RotateLeft(12);
			selected = b;
			d += a;

			selected ^= a;
			c += message + 0xA8304613U;
			selected &= d;
			message = ReadX64Message(ref source, 7);
			selected ^= b;
			c += selected;
			c = c.RotateLeft(17);
			selected = a;
			c += d;

			selected ^= d;
			b += message + 0xFD469501U;
			selected &= c;
			message = ReadX64Message(ref source, 8);
			selected ^= a;
			b += selected;
			b = b.RotateLeft(22);
			selected = d;
			b += c;

			selected ^= c;
			a += message + 0x698098D8U;
			selected &= b;
			message = ReadX64Message(ref source, 9);
			selected ^= d;
			a += selected;
			a = a.RotateLeft(7);
			selected = c;
			a += b;

			selected ^= b;
			d += message + 0x8B44F7AFU;
			selected &= a;
			message = ReadX64Message(ref source, 10);
			selected ^= c;
			d += selected;
			d = d.RotateLeft(12);
			selected = b;
			d += a;

			selected ^= a;
			c += message + 0xFFFF5BB1U;
			selected &= d;
			message = ReadX64Message(ref source, 11);
			selected ^= b;
			c += selected;
			c = c.RotateLeft(17);
			selected = a;
			c += d;

			selected ^= d;
			b += message + 0x895CD7BEU;
			selected &= c;
			message = ReadX64Message(ref source, 12);
			selected ^= a;
			b += selected;
			b = b.RotateLeft(22);
			selected = d;
			b += c;

			selected ^= c;
			a += message + 0x6B901122U;
			selected &= b;
			message = ReadX64Message(ref source, 13);
			selected ^= d;
			a += selected;
			a = a.RotateLeft(7);
			selected = c;
			a += b;

			selected ^= b;
			d += message + 0xFD987193U;
			selected &= a;
			message = ReadX64Message(ref source, 14);
			selected ^= c;
			d += selected;
			d = d.RotateLeft(12);
			selected = b;
			d += a;

			selected ^= a;
			c += message + 0xA679438EU;
			selected &= d;
			message = ReadX64Message(ref source, 15);
			selected ^= b;
			c += selected;
			c = c.RotateLeft(17);
			selected = a;
			c += d;

			selected ^= d;
			b += message + 0x49B40821U;
			selected &= c;
			message = ReadX64Message(ref source, 1);
			selected ^= a;
			b += selected;
			b = b.RotateLeft(22);
			selected = d;
			b += c;

			// Round 2.
			selected = c & ~d;
			a += message + 0xF61E2562U;
			selected2 = b & d;
			message = ReadX64Message(ref source, 6);
			a += selected;
			a += selected2;
			a = a.RotateLeft(5);
			a += b;

			selected = b & ~c;
			d += message + 0xC040B340U;
			selected2 = a & c;
			message = ReadX64Message(ref source, 11);
			d += selected;
			d += selected2;
			d = d.RotateLeft(9);
			d += a;

			selected = a & ~b;
			c += message + 0x265E5A51U;
			selected2 = d & b;
			message = ReadX64Message(ref source, 0);
			c += selected;
			c += selected2;
			c = c.RotateLeft(14);
			c += d;

			selected = d & ~a;
			b += message + 0xE9B6C7AAU;
			selected2 = c & a;
			message = ReadX64Message(ref source, 5);
			b += selected;
			b += selected2;
			b = b.RotateLeft(20);
			b += c;

			selected = c & ~d;
			a += message + 0xD62F105DU;
			selected2 = b & d;
			message = ReadX64Message(ref source, 10);
			a += selected;
			a += selected2;
			a = a.RotateLeft(5);
			a += b;

			selected = b & ~c;
			d += message + 0x02441453U;
			selected2 = a & c;
			message = ReadX64Message(ref source, 15);
			d += selected;
			d += selected2;
			d = d.RotateLeft(9);
			d += a;

			selected = a & ~b;
			c += message + 0xD8A1E681U;
			selected2 = d & b;
			message = ReadX64Message(ref source, 4);
			c += selected;
			c += selected2;
			c = c.RotateLeft(14);
			c += d;

			selected = d & ~a;
			b += message + 0xE7D3FBC8U;
			selected2 = c & a;
			message = ReadX64Message(ref source, 9);
			b += selected;
			b += selected2;
			b = b.RotateLeft(20);
			b += c;

			selected = c & ~d;
			a += message + 0x21E1CDE6U;
			selected2 = b & d;
			message = ReadX64Message(ref source, 14);
			a += selected;
			a += selected2;
			a = a.RotateLeft(5);
			a += b;

			selected = b & ~c;
			d += message + 0xC33707D6U;
			selected2 = a & c;
			message = ReadX64Message(ref source, 3);
			d += selected;
			d += selected2;
			d = d.RotateLeft(9);
			d += a;

			selected = a & ~b;
			c += message + 0xF4D50D87U;
			selected2 = d & b;
			message = ReadX64Message(ref source, 8);
			c += selected;
			c += selected2;
			c = c.RotateLeft(14);
			c += d;

			selected = d & ~a;
			b += message + 0x455A14EDU;
			selected2 = c & a;
			message = ReadX64Message(ref source, 13);
			b += selected;
			b += selected2;
			b = b.RotateLeft(20);
			b += c;

			selected = c & ~d;
			a += message + 0xA9E3E905U;
			selected2 = b & d;
			message = ReadX64Message(ref source, 2);
			a += selected;
			a += selected2;
			a = a.RotateLeft(5);
			a += b;

			selected = b & ~c;
			d += message + 0xFCEFA3F8U;
			selected2 = a & c;
			message = ReadX64Message(ref source, 7);
			d += selected;
			d += selected2;
			d = d.RotateLeft(9);
			d += a;

			selected = a & ~b;
			c += message + 0x676F02D9U;
			selected2 = d & b;
			message = ReadX64Message(ref source, 12);
			c += selected;
			c += selected2;
			c = c.RotateLeft(14);
			c += d;

			selected = d & ~a;
			b += message + 0x8D2A4C8AU;
			selected2 = c & a;
			message = ReadX64Message(ref source, 5);
			b += selected;
			b += selected2;
			b = b.RotateLeft(20);
			b += c;

			// Round 3.
			selected = c;

			a += message + 0xFFFA3942U;
			selected ^= d;
			message = ReadX64Message(ref source, 8);
			selected ^= b;
			a += selected;
			selected = b;
			a = a.RotateLeft(4);
			a += b;

			d += message + 0x8771F681U;
			selected ^= c;
			message = ReadX64Message(ref source, 11);
			selected ^= a;
			d += selected;
			d = d.RotateLeft(11);
			selected = a;
			d += a;

			c += message + 0x6D9D6122U;
			selected ^= b;
			message = ReadX64Message(ref source, 14);
			selected ^= d;
			c += selected;
			selected = d;
			c = c.RotateLeft(16);
			c += d;

			b += message + 0xFDE5380CU;
			selected ^= a;
			message = ReadX64Message(ref source, 1);
			selected ^= c;
			b += selected;
			b = b.RotateLeft(23);
			selected = c;
			b += c;

			a += message + 0xA4BEEA44U;
			selected ^= d;
			message = ReadX64Message(ref source, 4);
			selected ^= b;
			a += selected;
			selected = b;
			a = a.RotateLeft(4);
			a += b;

			d += message + 0x4BDECFA9U;
			selected ^= c;
			message = ReadX64Message(ref source, 7);
			selected ^= a;
			d += selected;
			d = d.RotateLeft(11);
			selected = a;
			d += a;

			c += message + 0xF6BB4B60U;
			selected ^= b;
			message = ReadX64Message(ref source, 10);
			selected ^= d;
			c += selected;
			selected = d;
			c = c.RotateLeft(16);
			c += d;

			b += message + 0xBEBFBC70U;
			selected ^= a;
			message = ReadX64Message(ref source, 13);
			selected ^= c;
			b += selected;
			b = b.RotateLeft(23);
			selected = c;
			b += c;

			a += message + 0x289B7EC6U;
			selected ^= d;
			message = ReadX64Message(ref source, 0);
			selected ^= b;
			a += selected;
			selected = b;
			a = a.RotateLeft(4);
			a += b;

			d += message + 0xEAA127FAU;
			selected ^= c;
			message = ReadX64Message(ref source, 3);
			selected ^= a;
			d += selected;
			d = d.RotateLeft(11);
			selected = a;
			d += a;

			c += message + 0xD4EF3085U;
			selected ^= b;
			message = ReadX64Message(ref source, 6);
			selected ^= d;
			c += selected;
			selected = d;
			c = c.RotateLeft(16);
			c += d;

			b += message + 0x04881D05U;
			selected ^= a;
			message = ReadX64Message(ref source, 9);
			selected ^= c;
			b += selected;
			b = b.RotateLeft(23);
			selected = c;
			b += c;

			a += message + 0xD9D4D039U;
			selected ^= d;
			message = ReadX64Message(ref source, 12);
			selected ^= b;
			a += selected;
			selected = b;
			a = a.RotateLeft(4);
			a += b;

			d += message + 0xE6DB99E5U;
			selected ^= c;
			message = ReadX64Message(ref source, 15);
			selected ^= a;
			d += selected;
			d = d.RotateLeft(11);
			selected = a;
			d += a;

			c += message + 0x1FA27CF8U;
			selected ^= b;
			message = ReadX64Message(ref source, 2);
			selected ^= d;
			c += selected;
			selected = d;
			c = c.RotateLeft(16);
			c += d;

			b += message + 0xC4AC5665U;
			selected ^= a;
			message = ReadX64Message(ref source, 0);
			selected ^= c;
			b += selected;
			b = b.RotateLeft(23);
			selected = c;
			b += c;

			// Round 4.
			selected = ~d;

			a += message + 0xF4292244U;
			selected |= b;
			message = ReadX64Message(ref source, 7);
			selected ^= c;
			a += selected;
			selected = uint.MaxValue;
			a = a.RotateLeft(6);
			selected ^= c;
			a += b;

			d += message + 0x432AFF97U;
			selected |= a;
			message = ReadX64Message(ref source, 14);
			selected ^= b;
			d += selected;
			selected = uint.MaxValue;
			d = d.RotateLeft(10);
			selected ^= b;
			d += a;

			c += message + 0xAB9423A7U;
			selected |= d;
			message = ReadX64Message(ref source, 5);
			selected ^= a;
			c += selected;
			selected = uint.MaxValue;
			c = c.RotateLeft(15);
			selected ^= a;
			c += d;

			b += message + 0xFC93A039U;
			selected |= c;
			message = ReadX64Message(ref source, 12);
			selected ^= d;
			b += selected;
			selected = uint.MaxValue;
			b = b.RotateLeft(21);
			selected ^= d;
			b += c;

			a += message + 0x655B59C3U;
			selected |= b;
			message = ReadX64Message(ref source, 3);
			selected ^= c;
			a += selected;
			selected = uint.MaxValue;
			a = a.RotateLeft(6);
			selected ^= c;
			a += b;

			d += message + 0x8F0CCC92U;
			selected |= a;
			message = ReadX64Message(ref source, 10);
			selected ^= b;
			d += selected;
			selected = uint.MaxValue;
			d = d.RotateLeft(10);
			selected ^= b;
			d += a;

			c += message + 0xFFEFF47DU;
			selected |= d;
			message = ReadX64Message(ref source, 1);
			selected ^= a;
			c += selected;
			selected = uint.MaxValue;
			c = c.RotateLeft(15);
			selected ^= a;
			c += d;

			b += message + 0x85845DD1U;
			selected |= c;
			message = ReadX64Message(ref source, 8);
			selected ^= d;
			b += selected;
			selected = uint.MaxValue;
			b = b.RotateLeft(21);
			selected ^= d;
			b += c;

			a += message + 0x6FA87E4FU;
			selected |= b;
			message = ReadX64Message(ref source, 15);
			selected ^= c;
			a += selected;
			selected = uint.MaxValue;
			a = a.RotateLeft(6);
			selected ^= c;
			a += b;

			d += message + 0xFE2CE6E0U;
			selected |= a;
			message = ReadX64Message(ref source, 6);
			selected ^= b;
			d += selected;
			selected = uint.MaxValue;
			d = d.RotateLeft(10);
			selected ^= b;
			d += a;

			c += message + 0xA3014314U;
			selected |= d;
			message = ReadX64Message(ref source, 13);
			selected ^= a;
			c += selected;
			selected = uint.MaxValue;
			c = c.RotateLeft(15);
			selected ^= a;
			c += d;

			b += message + 0x4E0811A1U;
			selected |= c;
			message = ReadX64Message(ref source, 4);
			selected ^= d;
			b += selected;
			selected = uint.MaxValue;
			b = b.RotateLeft(21);
			selected ^= d;
			b += c;

			a += message + 0xF7537E82U;
			selected |= b;
			message = ReadX64Message(ref source, 11);
			selected ^= c;
			a += selected;
			selected = uint.MaxValue;
			a = a.RotateLeft(6);
			selected ^= c;
			a += b;

			d += message + 0xBD3AF235U;
			selected |= a;
			message = ReadX64Message(ref source, 2);
			selected ^= b;
			d += selected;
			selected = uint.MaxValue;
			d = d.RotateLeft(10);
			selected ^= b;
			d += a;

			c += message + 0x2AD7D2BBU;
			selected |= d;
			message = ReadX64Message(ref source, 9);
			selected ^= a;
			c += selected;
			selected = uint.MaxValue;
			c = c.RotateLeft(15);
			selected ^= a;
			c += d;

			b += message + 0xEB86D391U;
			selected |= c;
			message = ReadX64Message(ref source, 0);
			selected ^= d;
			b += selected;
			selected = uint.MaxValue;
			b = b.RotateLeft(21);
			selected ^= d;
			b += c;

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
