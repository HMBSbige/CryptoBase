namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public sealed partial class XtsMode128<TDataCipher, TTweakCipher> : IBlockModeOneShot
	where TDataCipher : IBlock16Cipher<TDataCipher>
	where TTweakCipher : IBlock16Cipher<TTweakCipher>
{
	public string Name => "AES-XTS";

	public int BlockSize => 16;

	private const int Block = 16;

	private readonly TDataCipher _dataCipher;
	private readonly TTweakCipher _tweakCipher;
	private readonly bool _disposeCipher;

	public XtsMode128(TDataCipher dataCipher, TTweakCipher tweakCipher, bool disposeCipher = true)
	{
		_dataCipher = dataCipher;
		_tweakCipher = tweakCipher;
		_disposeCipher = disposeCipher;
	}

	public void Dispose()
	{
		if (_disposeCipher)
		{
			_dataCipher.Dispose();
			_tweakCipher.Dispose();
		}
	}

	public int GetMaxByteCount(int inputLength)
	{
		return inputLength;
	}

	public static void GetIv(in Span<byte> iv, in UInt128 dataUnitSeqNumber)
	{
		BinaryPrimitives.WriteUInt128LittleEndian(iv, dataUnitSeqNumber);
	}

	[SkipLocalsInit]
	public void Encrypt(in ReadOnlySpan<byte> iv, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, BlockSize, nameof(iv));
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));

		VectorBuffer16 ivBuffer = iv.AsVectorBuffer16();
		Vector128<byte> tweak = _tweakCipher.Encrypt(ivBuffer).V128;

		int left = source.Length % BlockSize;
		int size = source.Length - left;

		int length = size;
		int offset = 0;

		if (Avx512BW.IsSupported && Pclmulqdq.V512.IsSupported)
		{
			if (length >= 32 * Block)
			{
				int o = Encrypt32Avx512(ref tweak, source, destination, length);

				offset += o;
				length -= o;
			}

			if (length >= 16 * Block)
			{
				int o = Encrypt16Avx512(ref tweak, source.Slice(offset), destination.Slice(offset), length);

				offset += o;
				length -= o;
			}
		}

		if (Avx2.IsSupported && Pclmulqdq.V256.IsSupported)
		{
			if (length >= 8 * Block)
			{
				int o = Encrypt8Avx2(ref tweak, source.Slice(offset), destination.Slice(offset), length);

				offset += o;
				length -= o;
			}
		}

		if (length >= 8 * Block)
		{
			ref readonly byte sourceRef = ref source.Slice(offset).GetReference();
			ref byte destinationRef = ref destination.Slice(offset).GetReference();
			int i = 0;

			while (length >= 8 * Block)
			{
				Vector128<byte> t0 = tweak;
				Vector128<byte> t1 = Gf128MulV128(t0);
				Vector128<byte> t2 = Gf128MulV128(t1);
				Vector128<byte> t3 = Gf128MulV128(t2);
				Vector128<byte> t4 = Gf128MulV128(t3);
				Vector128<byte> t5 = Gf128MulV128(t4);
				Vector128<byte> t6 = Gf128MulV128(t5);
				Vector128<byte> t7 = Gf128MulV128(t6);
				tweak = Gf128MulV128(t7);

				VectorBuffer128 src = Unsafe.Add(ref Unsafe.AsRef(in sourceRef), i).AsVectorBuffer128();
				VectorBuffer128 xored = new VectorBuffer128
				{
					V128_0 = src.V128_0 ^ t0,
					V128_1 = src.V128_1 ^ t1,
					V128_2 = src.V128_2 ^ t2,
					V128_3 = src.V128_3 ^ t3,
					V128_4 = src.V128_4 ^ t4,
					V128_5 = src.V128_5 ^ t5,
					V128_6 = src.V128_6 ^ t6,
					V128_7 = src.V128_7 ^ t7
				};
				VectorBuffer128 encrypted = _dataCipher.Encrypt(xored);
				ref VectorBuffer128 dst = ref Unsafe.Add(ref destinationRef, i).AsVectorBuffer128();
				dst = new VectorBuffer128
				{
					V128_0 = encrypted.V128_0 ^ t0,
					V128_1 = encrypted.V128_1 ^ t1,
					V128_2 = encrypted.V128_2 ^ t2,
					V128_3 = encrypted.V128_3 ^ t3,
					V128_4 = encrypted.V128_4 ^ t4,
					V128_5 = encrypted.V128_5 ^ t5,
					V128_6 = encrypted.V128_6 ^ t6,
					V128_7 = encrypted.V128_7 ^ t7
				};

				i += 8 * Block;
				length -= 8 * Block;
			}

			offset += i;
		}

		while (length > 0)
		{
			VectorBuffer16 tweakBuf = new() { V128 = tweak };
			VectorBuffer16 src = source.Slice(offset).AsVectorBuffer16();
			VectorBuffer16 xored = src ^ tweakBuf;
			VectorBuffer16 encrypted = _dataCipher.Encrypt(xored);
			ref VectorBuffer16 dst = ref destination.Slice(offset).AsVectorBuffer16();
			dst = encrypted ^ tweakBuf;

			tweak = Gf128MulV128(tweak);

			offset += Block;
			length -= Block;
		}

		if (left is not 0)
		{
			VectorBuffer16 tweakBuf = new() { V128 = tweak };
			Span<byte> lastDst = destination.Slice(size - Block, Block);

			lastDst.Slice(0, left).CopyTo(destination.Slice(size));
			source.Slice(size).CopyTo(lastDst);

			VectorBuffer16 lastSrc = lastDst.AsVectorBuffer16();
			VectorBuffer16 enc = lastSrc ^ tweakBuf;
			enc = _dataCipher.Encrypt(enc);
			lastDst.AsVectorBuffer16() = enc ^ tweakBuf;
		}
	}

	[SkipLocalsInit]
	public void Decrypt(in ReadOnlySpan<byte> iv, in ReadOnlySpan<byte> source, in Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(iv.Length, BlockSize, nameof(iv));
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, BlockSize, nameof(source));
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));

		VectorBuffer16 ivBuffer = iv.AsVectorBuffer16();
		Vector128<byte> tweak = _tweakCipher.Encrypt(ivBuffer).V128;

		int left = source.Length % BlockSize;
		int size = source.Length - left - (BlockSize & (left | -left) >> 31);

		int length = size;
		int offset = 0;

		if (Avx512BW.IsSupported && Pclmulqdq.V512.IsSupported)
		{
			if (length >= 32 * Block)
			{
				int o = Decrypt32Avx512(ref tweak, source, destination, length);

				offset += o;
				length -= o;
			}

			if (length >= 16 * Block)
			{
				int o = Decrypt16Avx512(ref tweak, source.Slice(offset), destination.Slice(offset), length);

				offset += o;
				length -= o;
			}
		}

		if (Avx2.IsSupported && Pclmulqdq.V256.IsSupported)
		{
			if (length >= 8 * Block)
			{
				int o = Decrypt8Avx2(ref tweak, source.Slice(offset), destination.Slice(offset), length);

				offset += o;
				length -= o;
			}
		}

		if (length >= 8 * Block)
		{
			ref readonly byte sourceRef = ref source.Slice(offset).GetReference();
			ref byte destinationRef = ref destination.Slice(offset).GetReference();
			int i = 0;

			while (length >= 8 * Block)
			{
				Vector128<byte> t0 = tweak;
				Vector128<byte> t1 = Gf128MulV128(t0);
				Vector128<byte> t2 = Gf128MulV128(t1);
				Vector128<byte> t3 = Gf128MulV128(t2);
				Vector128<byte> t4 = Gf128MulV128(t3);
				Vector128<byte> t5 = Gf128MulV128(t4);
				Vector128<byte> t6 = Gf128MulV128(t5);
				Vector128<byte> t7 = Gf128MulV128(t6);
				tweak = Gf128MulV128(t7);

				VectorBuffer128 src = Unsafe.Add(ref Unsafe.AsRef(in sourceRef), i).AsVectorBuffer128();
				VectorBuffer128 xored = new VectorBuffer128
				{
					V128_0 = src.V128_0 ^ t0,
					V128_1 = src.V128_1 ^ t1,
					V128_2 = src.V128_2 ^ t2,
					V128_3 = src.V128_3 ^ t3,
					V128_4 = src.V128_4 ^ t4,
					V128_5 = src.V128_5 ^ t5,
					V128_6 = src.V128_6 ^ t6,
					V128_7 = src.V128_7 ^ t7
				};
				VectorBuffer128 decrypted = _dataCipher.Decrypt(xored);
				ref VectorBuffer128 dst = ref Unsafe.Add(ref destinationRef, i).AsVectorBuffer128();
				dst = new VectorBuffer128
				{
					V128_0 = decrypted.V128_0 ^ t0,
					V128_1 = decrypted.V128_1 ^ t1,
					V128_2 = decrypted.V128_2 ^ t2,
					V128_3 = decrypted.V128_3 ^ t3,
					V128_4 = decrypted.V128_4 ^ t4,
					V128_5 = decrypted.V128_5 ^ t5,
					V128_6 = decrypted.V128_6 ^ t6,
					V128_7 = decrypted.V128_7 ^ t7
				};

				i += 8 * Block;
				length -= 8 * Block;
			}

			offset += i;
		}

		while (length > 0)
		{
			VectorBuffer16 tweakBuf = new() { V128 = tweak };
			VectorBuffer16 src = source.Slice(offset).AsVectorBuffer16();
			VectorBuffer16 xored = src ^ tweakBuf;
			VectorBuffer16 decrypted = _dataCipher.Decrypt(xored);
			ref VectorBuffer16 dst = ref destination.Slice(offset).AsVectorBuffer16();
			dst = decrypted ^ tweakBuf;

			tweak = Gf128MulV128(tweak);

			offset += Block;
			length -= Block;
		}

		if (left is not 0)
		{
			VectorBuffer16 tweakBuf = new() { V128 = tweak };
			Vector128<byte> finalTweak = Gf128MulV128(tweak);
			VectorBuffer16 finalTweakBuf = new() { V128 = finalTweak };

			ReadOnlySpan<byte> lastSrc = source.Slice(size);
			Span<byte> lastDst = destination.Slice(size);

			VectorBuffer16 lastSrcBlock = lastSrc.AsVectorBuffer16();
			VectorBuffer16 dec = lastSrcBlock ^ finalTweakBuf;
			dec = _dataCipher.Decrypt(dec);
			lastDst.AsVectorBuffer16() = dec ^ finalTweakBuf;

			lastDst.Slice(0, left).CopyTo(lastDst.Slice(Block));
			lastSrc.Slice(Block, left).CopyTo(lastDst);

			VectorBuffer16 lastBlock = lastDst.AsVectorBuffer16();
			dec = lastBlock ^ tweakBuf;
			dec = _dataCipher.Decrypt(dec);
			lastDst.AsVectorBuffer16() = dec ^ tweakBuf;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> Gf128MulV128(Vector128<byte> tweak)
	{
		if (Sse2.IsSupported)
		{
			Vector128<int> carry = Sse2.Shuffle(tweak.AsInt32(), 0b00_01_00_11) >> 31;

			return (tweak.AsUInt64() << 1).AsByte() ^ carry.AsByte() & Vector128.Create(0x87, 1).AsByte();
		}

		Int128 val = Unsafe.As<Vector128<byte>, Int128>(ref tweak);
		val = val << 1 ^ val >> 127 & 0x87;
		return Unsafe.As<Int128, Vector128<byte>>(ref val);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> Gf128MulV128(Vector128<byte> tweak, [ConstantExpected(Min = 1, Max = 64)] int x)
	{
		if (x is 1)
		{
			return Gf128MulV128(tweak);
		}

		Vector128<ulong> tmp1 = tweak.AsUInt64() >>> 64 - x;

		Vector128<ulong> tmp2 = Pclmulqdq.CarrylessMultiply(tmp1, Vector128.Create(0x87UL), 0x01);

		tmp1 = Sse2.ShiftLeftLogical128BitLane(tmp1.AsByte(), 8).AsUInt64();

		return (tweak.AsUInt64() << x ^ tmp1 ^ tmp2).AsByte();
	}
}
