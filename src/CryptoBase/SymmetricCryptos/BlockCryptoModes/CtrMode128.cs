namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public sealed class CtrMode128<TBlockCipher> : IStreamCrypto where TBlockCipher : IBlock16Cipher<TBlockCipher>
{
	public string Name => _blockCipher.Name + "-CTR";

	private const int BlockSize = 16;

	private readonly TBlockCipher _blockCipher;
	private readonly bool _disposeCipher;

	private int _index;
	private readonly CryptoArrayPool<byte> _iv = new(BlockSize);
	private readonly CryptoArrayPool<byte> _counter = new(BlockSize);
	private readonly CryptoArrayPool<byte> _keyStream = new(BlockSize);

	public CtrMode128(TBlockCipher blockCipher, ReadOnlySpan<byte> iv, bool disposeCipher = true)
	{
		ArgumentOutOfRangeException.ThrowIfGreaterThan(iv.Length, BlockSize, nameof(iv));

		_blockCipher = blockCipher;
		_disposeCipher = disposeCipher;

		Span<byte> ivSpan = _iv.Span;
		ivSpan.Clear();
		iv.CopyTo(_iv.Span);

		Reset();
	}

	public void Dispose()
	{
		_iv.Dispose();
		_counter.Dispose();
		_keyStream.Dispose();

		if (_disposeCipher)
		{
			_blockCipher.Dispose();
		}
	}

	public void Reset()
	{
		_index = 0;
		_iv.Span.CopyTo(_counter.Span);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Update(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));

		int offset = 0;
		int left = source.Length;
		Span<byte> counter = _counter.Span;
		Span<byte> keyStream = _keyStream.Span;
		ref VectorBuffer16 c = ref counter.AsVectorBuffer16();
		ref VectorBuffer16 ks = ref keyStream.AsVectorBuffer16();

		VectorBuffer16 tmpc = c;
		VectorBuffer16 tmpks = ks;

		if (_index is not 0 && left > 0)
		{
			int r = BlockSize - _index;
			int n = Math.Min(r, left);

			FastUtils.XorLess16(tmpks.AsSpan().Slice(_index), source, destination, n);

			_index += n;
			_index &= BlockSize - 1;
			offset += n;
			left -= n;
		}

		if (left >= BlockSize)
		{
			int processed = UpdateBlock(ref tmpc, source.Slice(offset), destination.Slice(offset));
			offset += processed;
			left -= processed;
		}

		if (left > 0)
		{
			tmpks = UpdateKeyStream(ref tmpc);

			FastUtils.XorLess16(tmpks.AsSpan().Slice(_index), source.Slice(offset), destination.Slice(offset), left);

			_index = left;
		}

		c = tmpc;
		ks = tmpks;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private VectorBuffer16 UpdateKeyStream(scoped ref VectorBuffer16 counter)
	{
		VectorBuffer16 ks = _blockCipher.Encrypt(counter);

		if (Sse2.IsSupported)
		{
			counter.V128 = counter.V128.ReverseEndianness128().IncUInt128Le().ReverseEndianness128();
		}
		else
		{
			if (BitConverter.IsLittleEndian)
			{
				counter.U128 = BinaryPrimitives.ReverseEndianness(counter.U128) + 1;
				counter.U128 = BinaryPrimitives.ReverseEndianness(counter.U128);
			}
			else
			{
				++counter.U128;
			}
		}

		return ks;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int UpdateBlock(scoped ref VectorBuffer16 counter, ReadOnlySpan<byte> source, Span<byte> destination)
	{
		int i = 0;
		int left = source.Length;
		ref readonly byte sourceRef = ref source.GetReference();
		ref byte destinationRef = ref destination.GetReference();

		if (left >= 32 * BlockSize)
		{
			if (Avx512BW.IsSupported
				&& TBlockCipher.HardwareAcceleration.HasFlag(BlockCipherHardwareAcceleration.Block32V512)
				)
			{
				Vector512<byte> t0 = Vector512.Create(counter.V128);
				t0 = t0.ReverseEndianness128().AddUInt128Le0123();
				Vector512<byte> t1 = t0.AddUInt128Le4444();
				Vector512<byte> t2 = t1.AddUInt128Le4444();
				Vector512<byte> t3 = t2.AddUInt128Le4444();
				Vector512<byte> t4 = t3.AddUInt128Le4444();
				Vector512<byte> t5 = t4.AddUInt128Le4444();
				Vector512<byte> t6 = t5.AddUInt128Le4444();
				Vector512<byte> t7 = t6.AddUInt128Le4444();

				VectorBuffer512 tmp = new()
				{
					V512_0 = t0.ReverseEndianness128(),
					V512_1 = t1.ReverseEndianness128(),
					V512_2 = t2.ReverseEndianness128(),
					V512_3 = t3.ReverseEndianness128(),
					V512_4 = t4.ReverseEndianness128(),
					V512_5 = t5.ReverseEndianness128(),
					V512_6 = t6.ReverseEndianness128(),
					V512_7 = t7.ReverseEndianness128()
				};

				while (left >= 32 * BlockSize)
				{
					VectorBuffer512 ks = _blockCipher.EncryptV512(tmp);

					t0 = t7.AddUInt128Le4444();
					t1 = t0.AddUInt128Le4444();
					t2 = t1.AddUInt128Le4444();
					t3 = t2.AddUInt128Le4444();
					t4 = t3.AddUInt128Le4444();
					t5 = t4.AddUInt128Le4444();
					t6 = t5.AddUInt128Le4444();
					t7 = t6.AddUInt128Le4444();

					tmp.V512_0 = t0.ReverseEndianness128();
					tmp.V512_1 = t1.ReverseEndianness128();
					tmp.V512_2 = t2.ReverseEndianness128();
					tmp.V512_3 = t3.ReverseEndianness128();
					tmp.V512_4 = t4.ReverseEndianness128();
					tmp.V512_5 = t5.ReverseEndianness128();
					tmp.V512_6 = t6.ReverseEndianness128();
					tmp.V512_7 = t7.ReverseEndianness128();

					ref readonly VectorBuffer512 src = ref Unsafe.Add(ref Unsafe.AsRef(in sourceRef), i).AsVectorBuffer512();
					ref VectorBuffer512 dst = ref Unsafe.Add(ref destinationRef, i).AsVectorBuffer512();

					dst.V512_0 = src.V512_0 ^ ks.V512_0;
					dst.V512_1 = src.V512_1 ^ ks.V512_1;
					dst.V512_2 = src.V512_2 ^ ks.V512_2;
					dst.V512_3 = src.V512_3 ^ ks.V512_3;
					dst.V512_4 = src.V512_4 ^ ks.V512_4;
					dst.V512_5 = src.V512_5 ^ ks.V512_5;
					dst.V512_6 = src.V512_6 ^ ks.V512_6;
					dst.V512_7 = src.V512_7 ^ ks.V512_7;

					i += 32 * BlockSize;
					left -= 32 * BlockSize;
				}

				counter.V128 = tmp.Lower.V128_0;
			}
		}

		if (left >= 16 * BlockSize)
		{
			if (Avx2.IsSupported
				&& TBlockCipher.HardwareAcceleration.HasFlag(BlockCipherHardwareAcceleration.Block16V256)
				)
			{
				Vector256<byte> t0 = Vector256.Create(counter.V128);
				t0 = t0.ReverseEndianness128().AddUInt128Le01();
				Vector256<byte> t1 = t0.AddUInt128Le22();
				Vector256<byte> t2 = t1.AddUInt128Le22();
				Vector256<byte> t3 = t2.AddUInt128Le22();
				Vector256<byte> t4 = t3.AddUInt128Le22();
				Vector256<byte> t5 = t4.AddUInt128Le22();
				Vector256<byte> t6 = t5.AddUInt128Le22();
				Vector256<byte> t7 = t6.AddUInt128Le22();

				VectorBuffer256 tmp = new()
				{
					V256_0 = t0.ReverseEndianness128(),
					V256_1 = t1.ReverseEndianness128(),
					V256_2 = t2.ReverseEndianness128(),
					V256_3 = t3.ReverseEndianness128(),
					V256_4 = t4.ReverseEndianness128(),
					V256_5 = t5.ReverseEndianness128(),
					V256_6 = t6.ReverseEndianness128(),
					V256_7 = t7.ReverseEndianness128()
				};

				while (left >= 16 * BlockSize)
				{
					VectorBuffer256 ks = _blockCipher.EncryptV256(tmp);

					t0 = t7.AddUInt128Le22();
					t1 = t0.AddUInt128Le22();
					t2 = t1.AddUInt128Le22();
					t3 = t2.AddUInt128Le22();
					t4 = t3.AddUInt128Le22();
					t5 = t4.AddUInt128Le22();
					t6 = t5.AddUInt128Le22();
					t7 = t6.AddUInt128Le22();

					tmp.V256_0 = t0.ReverseEndianness128();
					tmp.V256_1 = t1.ReverseEndianness128();
					tmp.V256_2 = t2.ReverseEndianness128();
					tmp.V256_3 = t3.ReverseEndianness128();
					tmp.V256_4 = t4.ReverseEndianness128();
					tmp.V256_5 = t5.ReverseEndianness128();
					tmp.V256_6 = t6.ReverseEndianness128();
					tmp.V256_7 = t7.ReverseEndianness128();

					ref readonly VectorBuffer256 src = ref Unsafe.Add(ref Unsafe.AsRef(in sourceRef), i).AsVectorBuffer256();
					ref VectorBuffer256 dst = ref Unsafe.Add(ref destinationRef, i).AsVectorBuffer256();

					dst.V256_0 = src.V256_0 ^ ks.V256_0;
					dst.V256_1 = src.V256_1 ^ ks.V256_1;
					dst.V256_2 = src.V256_2 ^ ks.V256_2;
					dst.V256_3 = src.V256_3 ^ ks.V256_3;
					dst.V256_4 = src.V256_4 ^ ks.V256_4;
					dst.V256_5 = src.V256_5 ^ ks.V256_5;
					dst.V256_6 = src.V256_6 ^ ks.V256_6;
					dst.V256_7 = src.V256_7 ^ ks.V256_7;

					i += 16 * BlockSize;
					left -= 16 * BlockSize;
				}

				counter.V128 = tmp.V128_0;
			}
		}

		if (left >= 8 * BlockSize)
		{
			if (Avx2.IsSupported && TBlockCipher.HardwareAcceleration.HasFlag(BlockCipherHardwareAcceleration.Block8V256))
			{
				Vector256<byte> t0 = Vector256.Create(counter.V128);
				t0 = t0.ReverseEndianness128().AddUInt128Le01();
				Vector256<byte> t1 = t0.AddUInt128Le22();
				Vector256<byte> t2 = t1.AddUInt128Le22();
				Vector256<byte> t3 = t2.AddUInt128Le22();

				VectorBuffer128 tmp = new()
				{
					V256_0 = t0.ReverseEndianness128(),
					V256_1 = t1.ReverseEndianness128(),
					V256_2 = t2.ReverseEndianness128(),
					V256_3 = t3.ReverseEndianness128()
				};

				while (left >= 8 * BlockSize)
				{
					VectorBuffer128 ks = _blockCipher.EncryptV256(tmp);

					t0 = t3.AddUInt128Le22();
					t1 = t0.AddUInt128Le22();
					t2 = t1.AddUInt128Le22();
					t3 = t2.AddUInt128Le22();

					tmp.V256_0 = t0.ReverseEndianness128();
					tmp.V256_1 = t1.ReverseEndianness128();
					tmp.V256_2 = t2.ReverseEndianness128();
					tmp.V256_3 = t3.ReverseEndianness128();

					ref readonly VectorBuffer128 src = ref Unsafe.Add(ref Unsafe.AsRef(in sourceRef), i).AsVectorBuffer128();
					ref VectorBuffer128 dst = ref Unsafe.Add(ref destinationRef, i).AsVectorBuffer128();

					dst.V256_0 = src.V256_0 ^ ks.V256_0;
					dst.V256_1 = src.V256_1 ^ ks.V256_1;
					dst.V256_2 = src.V256_2 ^ ks.V256_2;
					dst.V256_3 = src.V256_3 ^ ks.V256_3;

					i += 8 * BlockSize;
					left -= 8 * BlockSize;
				}

				counter.V128 = tmp.V128_0;
			}
			else if (Sse2.IsSupported && TBlockCipher.HardwareAcceleration.HasFlag(BlockCipherHardwareAcceleration.Block8))
			{
				Vector128<byte> t1 = counter.V128.ReverseEndianness128().IncUInt128Le();
				Vector128<byte> t2 = t1.IncUInt128Le();
				Vector128<byte> t3 = t2.IncUInt128Le();
				Vector128<byte> t4 = t3.IncUInt128Le();
				Vector128<byte> t5 = t4.IncUInt128Le();
				Vector128<byte> t6 = t5.IncUInt128Le();
				Vector128<byte> t7 = t6.IncUInt128Le();

				VectorBuffer128 tmp = new()
				{
					V128_0 = counter.V128,
					V128_1 = t1.ReverseEndianness128(),
					V128_2 = t2.ReverseEndianness128(),
					V128_3 = t3.ReverseEndianness128(),
					V128_4 = t4.ReverseEndianness128(),
					V128_5 = t5.ReverseEndianness128(),
					V128_6 = t6.ReverseEndianness128(),
					V128_7 = t7.ReverseEndianness128()
				};

				while (left >= 8 * BlockSize)
				{
					VectorBuffer128 ks = _blockCipher.Encrypt(tmp);

					Vector128<byte> t0 = t7.IncUInt128Le();
					t1 = t0.IncUInt128Le();
					t2 = t1.IncUInt128Le();
					t3 = t2.IncUInt128Le();
					t4 = t3.IncUInt128Le();
					t5 = t4.IncUInt128Le();
					t6 = t5.IncUInt128Le();
					t7 = t6.IncUInt128Le();

					tmp.V128_0 = t0.ReverseEndianness128();
					tmp.V128_1 = t1.ReverseEndianness128();
					tmp.V128_2 = t2.ReverseEndianness128();
					tmp.V128_3 = t3.ReverseEndianness128();
					tmp.V128_4 = t4.ReverseEndianness128();
					tmp.V128_5 = t5.ReverseEndianness128();
					tmp.V128_6 = t6.ReverseEndianness128();
					tmp.V128_7 = t7.ReverseEndianness128();

					ref readonly VectorBuffer128 src = ref Unsafe.Add(ref Unsafe.AsRef(in sourceRef), i).AsVectorBuffer128();
					ref VectorBuffer128 dst = ref Unsafe.Add(ref destinationRef, i).AsVectorBuffer128();

					dst.V128_0 = src.V128_0 ^ ks.V128_0;
					dst.V128_1 = src.V128_1 ^ ks.V128_1;
					dst.V128_2 = src.V128_2 ^ ks.V128_2;
					dst.V128_3 = src.V128_3 ^ ks.V128_3;
					dst.V128_4 = src.V128_4 ^ ks.V128_4;
					dst.V128_5 = src.V128_5 ^ ks.V128_5;
					dst.V128_6 = src.V128_6 ^ ks.V128_6;
					dst.V128_7 = src.V128_7 ^ ks.V128_7;

					i += 8 * BlockSize;
					left -= 8 * BlockSize;
				}

				if (left >= 4 * BlockSize)
				{
					VectorBuffer64 ks = _blockCipher.Encrypt(tmp.Lower);

					Vector128<byte> t0 = t3.IncUInt128Le();
					t1 = t0.IncUInt128Le();

					tmp.V128_0 = t0.ReverseEndianness128();
					tmp.V128_1 = t1.ReverseEndianness128();

					ref readonly VectorBuffer64 src = ref Unsafe.Add(ref Unsafe.AsRef(in sourceRef), i).AsVectorBuffer64();
					ref VectorBuffer64 dst = ref Unsafe.Add(ref destinationRef, i).AsVectorBuffer64();

					dst.V128_0 = src.V128_0 ^ ks.V128_0;
					dst.V128_1 = src.V128_1 ^ ks.V128_1;
					dst.V128_2 = src.V128_2 ^ ks.V128_2;
					dst.V128_3 = src.V128_3 ^ ks.V128_3;

					i += 4 * BlockSize;
					left -= 4 * BlockSize;
				}

				if (left >= 2 * BlockSize)
				{
					Vector128<byte> t0 = t1.IncUInt128Le();

					VectorBuffer32 ks = _blockCipher.Encrypt(tmp.Lower.Lower);

					tmp.V128_0 = t0.ReverseEndianness128();

					ref readonly VectorBuffer32 src = ref Unsafe.Add(ref Unsafe.AsRef(in sourceRef), i).AsVectorBuffer32();
					ref VectorBuffer32 dst = ref Unsafe.Add(ref destinationRef, i).AsVectorBuffer32();

					dst.V128_0 = src.V128_0 ^ ks.V128_0;
					dst.V128_1 = src.V128_1 ^ ks.V128_1;

					i += 2 * BlockSize;
					left -= 2 * BlockSize;
				}

				counter.V128 = tmp.V128_0;
			}
		}

		while (left >= BlockSize)
		{
			VectorBuffer16 ks = UpdateKeyStream(ref counter);

			ref readonly VectorBuffer16 src = ref Unsafe.Add(ref Unsafe.AsRef(in sourceRef), i).AsVectorBuffer16();
			ref VectorBuffer16 dst = ref Unsafe.Add(ref destinationRef, i).AsVectorBuffer16();

			dst = src ^ ks;

			i += BlockSize;
			left -= BlockSize;
		}

		return source.Length - left;
	}
}
