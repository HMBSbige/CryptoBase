using CryptoBase.Hashes.Blake2;

namespace CryptoBase.Kdf.Argon2;

internal static unsafe class Argon2Core
{
	internal const int SyncPoints = 4;
	internal const int PrehashLength = 64;
	internal const int MinTagLength = 4;
	internal const uint Version = 0x13;

	// Prefetching data-independent references pays off once the memory outgrows the caches, but costs a little below this size.
	private const ulong PrefetchMinimumBytes = 16 << 20;

	// The exceptions report these parameter names, which the public DeriveKey methods share.
	internal static void ThrowIfInvalidArguments(Span<byte> destination, Argon2Parameters parameters, int maxDegreeOfParallelism)
	{
		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, MinTagLength, nameof(destination));
		ThreadPoolHelper.ThrowIfInvalidParallelism(maxDegreeOfParallelism);
		ThrowIfDefault(parameters);
	}

	internal static void ThrowIfDefault(Argon2Parameters parameters)
	{
		if (parameters.Parallelism is 0)
		{
			throw new ArgumentException("The parameters must be created by an Argon2Parameters constructor.", nameof(parameters));
		}
	}

	internal static void DeriveKey(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> secret, ReadOnlySpan<byte> associatedData, Argon2Type type, Argon2Parameters parameters, int maxDegreeOfParallelism, Span<byte> destination)
	{
		if (Argon2Vector512.IsSupported)
		{
			DeriveKey<Argon2Vector512>(password, salt, secret, associatedData, type, parameters, maxDegreeOfParallelism, destination);
		}
		else if (Argon2Vector256.IsSupported)
		{
			DeriveKey<Argon2Vector256>(password, salt, secret, associatedData, type, parameters, maxDegreeOfParallelism, destination);
		}
		else if (Argon2Vector128.IsSupported)
		{
			DeriveKey<Argon2Vector128>(password, salt, secret, associatedData, type, parameters, maxDegreeOfParallelism, destination);
		}
		else if (Argon2AdvSimd.IsSupported)
		{
			DeriveKey<Argon2AdvSimd>(password, salt, secret, associatedData, type, parameters, maxDegreeOfParallelism, destination);
		}
		else
		{
			DeriveKey<Argon2Scalar>(password, salt, secret, associatedData, type, parameters, maxDegreeOfParallelism, destination);
		}
	}

	[SkipLocalsInit]
	internal static void DeriveKey<TKernel>(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> secret, ReadOnlySpan<byte> associatedData, Argon2Type type, Argon2Parameters parameters, int maxDegreeOfParallelism, Span<byte> destination) where TKernel : IArgon2Kernel
	{
		Debug.Assert(TKernel.IsSupported);
		Debug.Assert(type is Argon2Type.Argon2d or Argon2Type.Argon2i or Argon2Type.Argon2id);
		Debug.Assert(parameters.Parallelism > 0);
		Debug.Assert(maxDegreeOfParallelism is -1 or > 0);
		Debug.Assert(destination.Length >= 4);

		int segmentLength = parameters.MemorySizeInKibibytes / (SyncPoints * parameters.Parallelism);
		ulong byteCount = (ulong)(uint)(parameters.Parallelism * segmentLength) * (SyncPoints * Argon2Block.SizeInBytes);

		if (byteCount > nuint.MaxValue)
		{
			throw new OutOfMemoryException();
		}

		using CryptoBuffer<byte> prehashBuffer = new(stackalloc byte[PrehashLength]);
		Span<byte> prehash = prehashBuffer.Span;
		ComputePrehash(password, salt, secret, associatedData, type, parameters, destination.Length, prehash);

		bool prefetchReferences = Sse.IsSupported && byteCount >= PrefetchMinimumBytes;

		Argon2Block* memory = (Argon2Block*)Argon2MemoryCache.Shared.Rent((nuint)byteCount);
		bool wiped = false;

		try
		{
			new Argon2Instance<TKernel>(memory, type, parameters.Parallelism, segmentLength, parameters.Iterations, maxDegreeOfParallelism, prefetchReferences).Derive(prehash, destination);
			wiped = true;
		}
		finally
		{
			if (wiped)
			{
				Argon2MemoryCache.Shared.Return((nint)memory, (nuint)byteCount);
			}
			else
			{
				Argon2MemoryCache.Discard((nint)memory, (nuint)byteCount);
			}
		}
	}

	[SkipLocalsInit]
	private static void ComputePrehash(ReadOnlySpan<byte> password, ReadOnlySpan<byte> salt, ReadOnlySpan<byte> secret, ReadOnlySpan<byte> associatedData, Argon2Type type, Argon2Parameters parameters, int tagLength, Span<byte> prehash)
	{
		Span<byte> header = stackalloc byte[6 * sizeof(uint)];
		BinaryPrimitives.WriteUInt32LittleEndian(header, (uint)parameters.Parallelism);
		BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(4), (uint)tagLength);
		BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(8), (uint)parameters.MemorySizeInKibibytes);
		BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(12), (uint)parameters.Iterations);
		BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(16), Version);
		BinaryPrimitives.WriteUInt32LittleEndian(header.Slice(20), (uint)type);

		Unsafe.SkipInit(out Blake2bState blake2b);

		try
		{
			blake2b.Initialize(PrehashLength);
			blake2b.Append(header);
			AppendWithLength(ref blake2b, password);
			AppendWithLength(ref blake2b, salt);
			AppendWithLength(ref blake2b, secret);
			AppendWithLength(ref blake2b, associatedData);
			blake2b.Finalize(prehash, PrehashLength);
		}
		finally
		{
			blake2b.ZeroMemory();
		}
	}

	[SkipLocalsInit]
	private static void AppendWithLength(ref Blake2bState blake2b, ReadOnlySpan<byte> data)
	{
		Span<byte> length = stackalloc byte[sizeof(uint)];
		BinaryPrimitives.WriteUInt32LittleEndian(length, (uint)data.Length);
		blake2b.Append(length);
		blake2b.Append(data);
	}

	[SkipLocalsInit]
	internal static void HashVariable(ReadOnlySpan<byte> input, Span<byte> destination)
	{
		Span<byte> outputLength = stackalloc byte[sizeof(uint)];
		BinaryPrimitives.WriteUInt32LittleEndian(outputLength, (uint)destination.Length);
		Unsafe.SkipInit(out Blake2bState blake2b);
		Unsafe.SkipInit(out InlineArray64<byte> chainBuffer);
		Span<byte> chain = chainBuffer;

		try
		{
			blake2b.Initialize(Math.Min(destination.Length, Blake2bState.MaxHashSizeInBytes));
			blake2b.Append(outputLength);
			blake2b.Append(input);

			if (destination.Length <= Blake2bState.MaxHashSizeInBytes)
			{
				blake2b.Finalize(destination, destination.Length);
				return;
			}

			blake2b.Finalize(chain, Blake2bState.MaxHashSizeInBytes);

			while (true)
			{
				chain.Slice(0, Blake2bState.MaxHashSizeInBytes / 2).CopyTo(destination);
				destination = destination.Slice(Blake2bState.MaxHashSizeInBytes / 2);

				if (destination.Length <= Blake2bState.MaxHashSizeInBytes)
				{
					break;
				}

				blake2b.Initialize(Blake2bState.MaxHashSizeInBytes);
				blake2b.Append(chain);
				blake2b.Finalize(chain, Blake2bState.MaxHashSizeInBytes);
			}

			blake2b.Initialize(destination.Length);
			blake2b.Append(chain);
			blake2b.Finalize(destination, destination.Length);
		}
		finally
		{
			chain.ZeroMemory();
			blake2b.ZeroMemory();
		}
	}
}
