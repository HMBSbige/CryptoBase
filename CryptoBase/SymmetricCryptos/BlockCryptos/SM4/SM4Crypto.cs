using CryptoBase.Abstractions.SymmetricCryptos;
using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Runtime.Intrinsics.X86;

namespace CryptoBase.SymmetricCryptos.BlockCryptos.SM4
{
	public class SM4Crypto : BlockCryptoBase
	{
		public override string Name => @"SM4";

		public sealed override int BlockSize => 16;

		private static ReadOnlySpan<byte> S => new byte[]
		{
			0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
			0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
			0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
			0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
			0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
			0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
			0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
			0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
			0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
			0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
			0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
			0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
			0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
			0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
			0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
			0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
		};

		private static readonly uint[] Ck =
		{
			0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
			0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
			0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
			0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
			0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
			0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
			0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
			0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
		};

		private readonly uint[] _rk;

		#region Base

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static uint T(uint b)
		{
			b = SubByte(b);
			return b ^ b.RotateLeft(2) ^ b.RotateLeft(10) ^ b.RotateLeft(18) ^ b.RotateLeft(24);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static uint L1(uint b)
		{
			return b ^ b.RotateLeft(13) ^ b.RotateLeft(23);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static uint SubByte(uint a)
		{
			uint b0 = S[(byte)(a >> 24)];
			uint b1 = S[(byte)(a >> 16 & 0xFF)];
			uint b2 = S[(byte)(a >> 8 & 0xFF)];
			var b3 = S[(byte)(a & 0xFF)];

			return b0 << 24 | b1 << 16 | b2 << 8 | b3;
		}

		#endregion

		public SM4Crypto(byte[] key)
		{
			if (key.Length is not 16)
			{
				throw new ArgumentException(@"Key length must be 16 bytes", nameof(key));
			}

			_rk = ArrayPool<uint>.Shared.Rent(32);

			var span = key.AsSpan();
			var k0 = BinaryPrimitives.ReadUInt32BigEndian(span) ^ 0xa3b1bac6;
			var k1 = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(4)) ^ 0x56aa3350;
			var k2 = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(8)) ^ 0x677d9197;
			var k3 = BinaryPrimitives.ReadUInt32BigEndian(span.Slice(12)) ^ 0xb27022dc;

			for (var i = 0; i < 32; i += 4)
			{
				k0 ^= L1(SubByte(k1 ^ k2 ^ k3 ^ Ck[i + 0]));
				_rk[i + 0] = k0;

				k1 ^= L1(SubByte(k2 ^ k3 ^ k0 ^ Ck[i + 1]));
				_rk[i + 1] = k1;

				k2 ^= L1(SubByte(k3 ^ k0 ^ k1 ^ Ck[i + 2]));
				_rk[i + 2] = k2;

				k3 ^= L1(SubByte(k0 ^ k1 ^ k2 ^ Ck[i + 3]));
				_rk[i + 3] = k3;
			}
		}

		public override void Encrypt(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			base.Encrypt(source, destination);

			var x0 = BinaryPrimitives.ReadUInt32BigEndian(source);
			var x1 = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(4));
			var x2 = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(8));
			var x3 = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(12));

			for (var i = 0; i < 32; i += 4)
			{
				x0 ^= T(x1 ^ x2 ^ x3 ^ _rk[i + 0]);
				x1 ^= T(x0 ^ x2 ^ x3 ^ _rk[i + 1]);
				x2 ^= T(x0 ^ x1 ^ x3 ^ _rk[i + 2]);
				x3 ^= T(x0 ^ x1 ^ x2 ^ _rk[i + 3]);
			}

			BinaryPrimitives.WriteUInt32BigEndian(destination, x3);
			BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(4), x2);
			BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(8), x1);
			BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(12), x0);
		}

		public override void Decrypt(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			base.Decrypt(source, destination);

			var x0 = BinaryPrimitives.ReadUInt32BigEndian(source);
			var x1 = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(4));
			var x2 = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(8));
			var x3 = BinaryPrimitives.ReadUInt32BigEndian(source.Slice(12));

			for (var i = 28; i >= 0; i -= 4)
			{
				x0 ^= T(x1 ^ x2 ^ x3 ^ _rk[i + 3]);
				x1 ^= T(x0 ^ x2 ^ x3 ^ _rk[i + 2]);
				x2 ^= T(x0 ^ x1 ^ x3 ^ _rk[i + 1]);
				x3 ^= T(x0 ^ x1 ^ x2 ^ _rk[i + 0]);
			}

			BinaryPrimitives.WriteUInt32BigEndian(destination, x3);
			BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(4), x2);
			BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(8), x1);
			BinaryPrimitives.WriteUInt32BigEndian(destination.Slice(12), x0);
		}

		public override void Encrypt4(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			if (Aes.IsSupported && Sse2.IsSupported && Ssse3.IsSupported)
			{
				if (source.Length < BlockSize << 2)
				{
					throw new ArgumentException(string.Empty, nameof(source));
				}

				if (destination.Length < BlockSize << 2)
				{
					throw new ArgumentException(string.Empty, nameof(destination));
				}

				SM4Utils.Encrypt4(_rk, source, destination);
				return;
			}

			base.Encrypt4(source, destination);
		}

		public override void Dispose()
		{
			base.Dispose();

			ArrayPool<uint>.Shared.Return(_rk);
		}
	}
}
