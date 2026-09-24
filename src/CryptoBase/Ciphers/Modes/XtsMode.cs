using CryptoBase.Ciphers.Blocks.Aes;
using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Ciphers.Modes;

/// <summary>Provides XTS with ciphertext stealing for data units of at least 16 bytes.</summary>
public sealed class XtsMode<TBlockCipher> : IDataUnitCipher<XtsMode<TBlockCipher>> where TBlockCipher : IBlockCipher<TBlockCipher>
{
	private readonly TBlockCipher _dataCipher;
	private readonly TBlockCipher _tweakCipher;

	/// <inheritdoc />
	public static int TweakSize => 16;

	/// <summary>Initializes the cipher with the supplied block cipher instances.</summary>
	private XtsMode(TBlockCipher dataCipher, TBlockCipher tweakCipher)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(TBlockCipher.BlockSize, 16);
		_dataCipher = dataCipher;
		_tweakCipher = tweakCipher;
	}

	/// <summary>Creates XTS from the concatenated data and tweak keys.</summary>
	public static XtsMode<TBlockCipher> Create(scoped ReadOnlySpan<byte> key)
	{
		if (key.Length is 0 || key.Length % 2 is not 0)
		{
			throw new ArgumentException("XTS requires two equally sized keys.", nameof(key));
		}

		return Create(key.Slice(0, key.Length / 2), key.Slice(key.Length / 2));
	}

	/// <summary>Creates XTS from equally sized data and tweak keys.</summary>
	public static XtsMode<TBlockCipher> Create(scoped ReadOnlySpan<byte> dataKey, scoped ReadOnlySpan<byte> tweakKey)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(TBlockCipher.BlockSize, 16);
		ArgumentOutOfRangeException.ThrowIfNotEqual(dataKey.Length, tweakKey.Length, nameof(tweakKey));
		TBlockCipher data = TBlockCipher.Create(dataKey);

		try
		{
			return new XtsMode<TBlockCipher>(data, TBlockCipher.Create(tweakKey));
		}
		catch
		{
			data.Dispose();
			throw;
		}
	}

	/// <inheritdoc />
	public void Dispose()
	{
		_dataCipher.Dispose();
		_tweakCipher.Dispose();
	}

	/// <inheritdoc />
	public void Encrypt(scoped ReadOnlySpan<byte> tweak, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		Transform(tweak, source, destination, false);
	}

	/// <inheritdoc />
	public void Decrypt(scoped ReadOnlySpan<byte> tweak, scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
	{
		Transform(tweak, source, destination, true);
	}

	[SkipLocalsInit]
	private void Transform(ReadOnlySpan<byte> tweakInput, ReadOnlySpan<byte> source, Span<byte> destination, bool decrypt)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(tweakInput.Length, 16, nameof(tweakInput));
		ArgumentOutOfRangeException.ThrowIfLessThan(source.Length, 16, nameof(source));
		CipherBufferGuard.Output(source, destination);
		Vector128<byte> initialTweak = default;
		_tweakCipher.EncryptBlock(tweakInput, initialTweak.AsSpan());
		Vector128<byte> tweak = initialTweak;
		int tail = source.Length % 16;
		int fullLength = tail is 0 ? source.Length : source.Length - tail - 16;
		Span<byte> tweaks = stackalloc byte[2048];
		Span<byte> batch = stackalloc byte[32];

		try
		{
			int offset = 0;

			while (offset < fullLength)
			{
				int length = Math.Min(2048, fullLength - offset);
				int i = 0;

				if (Avx512BW.IsSupported && Pclmulqdq.V512.IsSupported)
				{
					Vector128<byte> t1 = Multiply(tweak);
					Vector128<byte> t2 = Multiply(t1);
					Vector128<byte> t3 = Multiply(t2);
					Vector512<byte> lanes = Vector512.Create(Vector256.Create(tweak, t1), Vector256.Create(t2, t3));

					for (; i <= length - 64; i += 64)
					{
						lanes.StoreUnsafe(ref tweaks.GetReference(), (nuint)i);
						Vector512<ulong> carry = lanes.AsUInt64() >>> 60;
						Vector512<ulong> reduction = Pclmulqdq.V512.CarrylessMultiply(carry, Vector512.Create(0x87UL), 0x01);
						lanes = (lanes.AsUInt64() << 4 ^ Avx512BW.ShiftLeftLogical128BitLane(carry.AsByte(), 8).AsUInt64() ^ reduction).AsByte();
					}

					tweak = lanes.GetLower().GetLower();
				}
				else if (Avx2.IsSupported && Pclmulqdq.V256.IsSupported && length >= 512)
				{
					Vector256<byte> t0 = Vector256.Create(tweak, Multiply(tweak));
					Vector256<byte> t1 = MultiplyPower(t0, 2);
					Vector256<byte> t2 = MultiplyPower(t0, 4);
					Vector256<byte> t3 = MultiplyPower(t0, 6);

					for (; i <= length - 128; i += 128)
					{
						t0.StoreUnsafe(ref tweaks.GetReference(), (nuint)i);
						t1.StoreUnsafe(ref tweaks.GetReference(), (nuint)(i + 32));
						t2.StoreUnsafe(ref tweaks.GetReference(), (nuint)(i + 64));
						t3.StoreUnsafe(ref tweaks.GetReference(), (nuint)(i + 96));
						t0 = MultiplyPower(t0, 8);
						t1 = MultiplyPower(t1, 8);
						t2 = MultiplyPower(t2, 8);
						t3 = MultiplyPower(t3, 8);
					}

					tweak = t0.GetLower();
				}
				else if (Pclmulqdq.IsSupported)
				{
					for (; i <= length - 128; i += 128)
					{
						tweak.StoreUnsafe(ref tweaks.GetReference(), (nuint)(i + 0));
						MultiplyPower(tweak, 1).StoreUnsafe(ref tweaks.GetReference(), (nuint)(i + 16));
						MultiplyPower(tweak, 2).StoreUnsafe(ref tweaks.GetReference(), (nuint)(i + 32));
						MultiplyPower(tweak, 3).StoreUnsafe(ref tweaks.GetReference(), (nuint)(i + 48));
						MultiplyPower(tweak, 4).StoreUnsafe(ref tweaks.GetReference(), (nuint)(i + 64));
						MultiplyPower(tweak, 5).StoreUnsafe(ref tweaks.GetReference(), (nuint)(i + 80));
						MultiplyPower(tweak, 6).StoreUnsafe(ref tweaks.GetReference(), (nuint)(i + 96));
						MultiplyPower(tweak, 7).StoreUnsafe(ref tweaks.GetReference(), (nuint)(i + 112));
						tweak = MultiplyPower(tweak, 8);
					}
				}

				for (; i < length; i += 16)
				{
					tweak.StoreUnsafe(ref tweaks.GetReference(), (nuint)i);
					tweak = Multiply(tweak);
				}

				Span<byte> buffer = destination.Slice(offset, length);

				if (_dataCipher is not AesCipher aes || !aes.TryTransformXex(source.Slice(offset, length), tweaks, buffer, decrypt))
				{
					FastUtils.Xor(tweaks, source.Slice(offset), buffer, length);

					if (decrypt)
					{
						_dataCipher.DecryptBlocks(buffer, buffer);
					}
					else
					{
						_dataCipher.EncryptBlocks(buffer, buffer);
					}

					FastUtils.Xor(tweaks, buffer, buffer, length);
				}

				offset += length;
			}

			if (tail is not 0)
			{
				Span<byte> last = batch.Slice(0, 16);
				Span<byte> partial = batch.Slice(16, tail);
				source.Slice(offset, 16).CopyTo(last);
				source.Slice(offset + 16, tail).CopyTo(partial);
				Vector128<byte> next = Multiply(tweak);
				TransformBlock(decrypt ? next : tweak, last, decrypt);
				last.Slice(0, tail).CopyTo(destination.Slice(offset + 16, tail));
				partial.CopyTo(last);
				TransformBlock(decrypt ? tweak : next, last, decrypt);
				last.CopyTo(destination.Slice(offset, 16));
			}
		}
		finally
		{
			batch.ZeroMemory();
		}
	}

	private void TransformBlock(Vector128<byte> tweak, Span<byte> block, bool decrypt)
	{
		Vector128<byte> value = Vector128.LoadUnsafe(ref block.GetReference()) ^ tweak;

		if (decrypt)
		{
			_dataCipher.DecryptBlock(value.AsReadOnlySpan(), value.AsSpan());
		}
		else
		{
			_dataCipher.EncryptBlock(value.AsReadOnlySpan(), value.AsSpan());
		}

		(value ^ tweak).StoreUnsafe(ref block.GetReference());
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector256<byte> MultiplyPower(Vector256<byte> tweak, [ConstantExpected(Min = 1, Max = 8)] byte power)
	{
		Vector256<ulong> carry = tweak.AsUInt64() >>> 64 - power;
		Vector256<ulong> reduction = Pclmulqdq.V256.CarrylessMultiply(carry, Vector256.Create(0x87UL), 0x01);
		return (tweak.AsUInt64() << power ^ Avx2.ShiftLeftLogical128BitLane(carry, 8) ^ reduction).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> MultiplyPower(Vector128<byte> tweak, [ConstantExpected(Min = 1, Max = 8)] byte power)
	{
		Vector128<ulong> carry = tweak.AsUInt64() >>> 64 - power;
		Vector128<ulong> reduction = Pclmulqdq.CarrylessMultiply(carry, Vector128.Create(0x87UL), 0x01);
		return (tweak.AsUInt64() << power ^ Sse2.ShiftLeftLogical128BitLane(carry, 8) ^ reduction).AsByte();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	private static Vector128<byte> Multiply(Vector128<byte> tweak)
	{
		if (Sse2.IsSupported || AdvSimd.Arm64.IsSupported)
		{
			Vector128<byte> carry = Sse2.IsSupported
				? (Sse2.Shuffle(tweak.AsInt32(), 0b00_01_00_11) >> 31).AsByte()
				: (AdvSimd.ExtractVector128(tweak.AsInt64(), tweak.AsInt64(), 1) >> 63).AsByte();
			return (tweak.AsUInt64() << 1).AsByte() ^ carry & Vector128.Create(0x87UL, 1UL).AsByte();
		}

		UInt128 value = BinaryPrimitives.ReadUInt128LittleEndian(tweak.AsReadOnlySpan());
		value = value << 1 ^ (UInt128)((Int128)value >> 127) & 0x87;
		BinaryPrimitives.WriteUInt128LittleEndian(tweak.AsSpan(), value);
		return tweak;
	}
}

/// <summary>Provides XTS tweak encoding.</summary>
public static class XtsMode
{
	/// <summary>Writes the data-unit number as a little-endian tweak.</summary>
	public static void GetIV(Span<byte> iv, UInt128 dataUnitSeqNumber)
	{
		BinaryPrimitives.WriteUInt128LittleEndian(iv, dataUnitSeqNumber);
	}
}
