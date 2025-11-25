namespace CryptoBase.Abstractions;

public static class SpanExtentions
{
	extension<T>(ref T reference) where T : unmanaged, allows ref struct
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Span<byte> AsSpan()
		{
			return MemoryMarshal.CreateSpan(ref Unsafe.As<T, byte>(ref reference), Unsafe.SizeOf<T>());
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ReadOnlySpan<byte> AsReadOnlySpan()
		{
			return MemoryMarshal.CreateReadOnlySpan(ref Unsafe.As<T, byte>(ref reference), Unsafe.SizeOf<T>());
		}
	}

	extension(ref byte reference)
	{
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref T As<T>() where T : allows ref struct
		{
			return ref Unsafe.As<byte, T>(ref reference);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer16 AsVectorBuffer16()
		{
			return ref As<VectorBuffer16>(ref reference);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer32 AsVectorBuffer32()
		{
			return ref As<VectorBuffer32>(ref reference);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer64 AsVectorBuffer64()
		{
			return ref As<VectorBuffer64>(ref reference);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer128 AsVectorBuffer128()
		{
			return ref As<VectorBuffer128>(ref reference);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer256 AsVectorBuffer256()
		{
			return ref As<VectorBuffer256>(ref reference);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer512 AsVectorBuffer512()
		{
			return ref As<VectorBuffer512>(ref reference);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer1024 AsVectorBuffer1024()
		{
			return ref As<VectorBuffer1024>(ref reference);
		}
	}

	extension<T>(ReadOnlySpan<T> span)
	{
		/// <inheritdoc cref="MemoryMarshal.GetReference{T}(ReadOnlySpan{T})" />
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref T GetReference()
		{
			return ref MemoryMarshal.GetReference(span);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref TTo As<TTo>() where TTo : allows ref struct
		{
			return ref Unsafe.As<T, TTo>(ref GetReference(span));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer16 AsVectorBuffer16()
		{
			return ref As<T, VectorBuffer16>(span);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer32 AsVectorBuffer32()
		{
			return ref As<T, VectorBuffer32>(span);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer64 AsVectorBuffer64()
		{
			return ref As<T, VectorBuffer64>(span);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer128 AsVectorBuffer128()
		{
			return ref As<T, VectorBuffer128>(span);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer256 AsVectorBuffer256()
		{
			return ref As<T, VectorBuffer256>(span);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer512 AsVectorBuffer512()
		{
			return ref As<T, VectorBuffer512>(span);
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer1024 AsVectorBuffer1024()
		{
			return ref As<T, VectorBuffer1024>(span);
		}
	}
}
