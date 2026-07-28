namespace CryptoBase.SymmetricCryptos.BlockCryptoModes;

public abstract class CtrMode128Core<TBlockCipher, TIncrementer> : IStreamCrypto
	where TBlockCipher : IBlock16Cipher<TBlockCipher>
	where TIncrementer : struct, ICtrIncrementer
{
	public string Name => _blockCipher.Name + @"-CTR";

	private const int BlockSize = 16;

	private readonly TBlockCipher _blockCipher;
	private readonly bool _disposeCipher;

	private int _index;
	private VectorBuffer16 _iv;
	private VectorBuffer16 _counter;
	private VectorBuffer16 _keyStream;

	private protected CtrMode128Core(TBlockCipher blockCipher, ReadOnlySpan<byte> iv, bool disposeCipher)
	{
		_blockCipher = blockCipher;
		_disposeCipher = disposeCipher;

		SetIv(iv);
	}

	public void SetIv(ReadOnlySpan<byte> iv)
	{
		ArgumentOutOfRangeException.ThrowIfGreaterThan(iv.Length, BlockSize, nameof(iv));

		_iv = default;
		iv.CopyTo(_iv.AsSpan());

		Reset();
	}

	public void Dispose()
	{
		CryptographicOperations.ZeroMemory(_iv.AsSpan());
		CryptographicOperations.ZeroMemory(_counter.AsSpan());
		CryptographicOperations.ZeroMemory(_keyStream.AsSpan());

		if (_disposeCipher)
		{
			_blockCipher.Dispose();
		}

		GC.SuppressFinalize(this);
	}

	public void Reset()
	{
		_index = 0;
		_counter = _iv;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public void Update(ReadOnlySpan<byte> source, Span<byte> destination)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, source.Length, nameof(destination));

		int offset = 0;
		int left = source.Length;

		if (_index is not 0 && left > 0)
		{
			int r = BlockSize - _index;
			int n = Math.Min(r, left);

			FastUtils.XorLess16(_keyStream.AsSpan().Slice(_index), source, destination, n);

			_index += n;
			_index &= BlockSize - 1;
			offset += n;
			left -= n;
		}

		if (left >= BlockSize)
		{
			int processed = UpdateBlock(ref _counter, source.Slice(offset), destination.Slice(offset));
			offset += processed;
			left -= processed;
		}

		if (left > 0)
		{
			_keyStream = UpdateKeyStream(ref _counter);

			FastUtils.XorLess16(_keyStream.AsSpan().Slice(_index), source.Slice(offset), destination.Slice(offset), left);

			_index = left;
		}
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private VectorBuffer16 UpdateKeyStream(ref VectorBuffer16 counter)
	{
		VectorBuffer16 ks = _blockCipher.Encrypt(counter);

		if (Sse2.IsSupported)
		{
			counter.V128 = TIncrementer.Inc(counter.V128.ReverseEndianness128()).ReverseEndianness128();
		}
		else
		{
			TIncrementer.IncSoftware(ref counter);
		}

		return ks;
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private int UpdateBlock(ref VectorBuffer16 counter, ReadOnlySpan<byte> source, Span<byte> destination)
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
				t0 = TIncrementer.Add0123(t0.ReverseEndianness128());
				Vector512<byte> t1 = TIncrementer.Add4444(t0);
				Vector512<byte> t2 = TIncrementer.Add4444(t1);
				Vector512<byte> t3 = TIncrementer.Add4444(t2);
				Vector512<byte> t4 = TIncrementer.Add4444(t3);
				Vector512<byte> t5 = TIncrementer.Add4444(t4);
				Vector512<byte> t6 = TIncrementer.Add4444(t5);
				Vector512<byte> t7 = TIncrementer.Add4444(t6);

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

					t0 = TIncrementer.Add4444(t7);
					t1 = TIncrementer.Add4444(t0);
					t2 = TIncrementer.Add4444(t1);
					t3 = TIncrementer.Add4444(t2);
					t4 = TIncrementer.Add4444(t3);
					t5 = TIncrementer.Add4444(t4);
					t6 = TIncrementer.Add4444(t5);
					t7 = TIncrementer.Add4444(t6);

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
				t0 = TIncrementer.Add01(t0.ReverseEndianness128());
				Vector256<byte> t1 = TIncrementer.Add22(t0);
				Vector256<byte> t2 = TIncrementer.Add22(t1);
				Vector256<byte> t3 = TIncrementer.Add22(t2);
				Vector256<byte> t4 = TIncrementer.Add22(t3);
				Vector256<byte> t5 = TIncrementer.Add22(t4);
				Vector256<byte> t6 = TIncrementer.Add22(t5);
				Vector256<byte> t7 = TIncrementer.Add22(t6);

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

					t0 = TIncrementer.Add22(t7);
					t1 = TIncrementer.Add22(t0);
					t2 = TIncrementer.Add22(t1);
					t3 = TIncrementer.Add22(t2);
					t4 = TIncrementer.Add22(t3);
					t5 = TIncrementer.Add22(t4);
					t6 = TIncrementer.Add22(t5);
					t7 = TIncrementer.Add22(t6);

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
				t0 = TIncrementer.Add01(t0.ReverseEndianness128());
				Vector256<byte> t1 = TIncrementer.Add22(t0);
				Vector256<byte> t2 = TIncrementer.Add22(t1);
				Vector256<byte> t3 = TIncrementer.Add22(t2);

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

					t0 = TIncrementer.Add22(t3);
					t1 = TIncrementer.Add22(t0);
					t2 = TIncrementer.Add22(t1);
					t3 = TIncrementer.Add22(t2);

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
				Vector128<byte> t1 = TIncrementer.Inc(counter.V128.ReverseEndianness128());
				Vector128<byte> t2 = TIncrementer.Inc(t1);
				Vector128<byte> t3 = TIncrementer.Inc(t2);
				Vector128<byte> t4 = TIncrementer.Inc(t3);
				Vector128<byte> t5 = TIncrementer.Inc(t4);
				Vector128<byte> t6 = TIncrementer.Inc(t5);
				Vector128<byte> t7 = TIncrementer.Inc(t6);

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

					Vector128<byte> t0 = TIncrementer.Inc(t7);
					t1 = TIncrementer.Inc(t0);
					t2 = TIncrementer.Inc(t1);
					t3 = TIncrementer.Inc(t2);
					t4 = TIncrementer.Inc(t3);
					t5 = TIncrementer.Inc(t4);
					t6 = TIncrementer.Inc(t5);
					t7 = TIncrementer.Inc(t6);

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

					Vector128<byte> t0 = TIncrementer.Inc(t3);
					t1 = TIncrementer.Inc(t0);

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
					Vector128<byte> t0 = TIncrementer.Inc(t1);

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
