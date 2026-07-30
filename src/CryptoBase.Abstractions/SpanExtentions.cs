namespace CryptoBase.Abstractions;

/// <summary>
/// Provides low-level span and reference reinterpretation extensions.
/// </summary>
public static class SpanExtentions
{
	extension<T>(ref T reference) where T : unmanaged
	{
		/// <summary>
		/// Creates a writable byte span over the referenced value.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public Span<byte> AsSpan()
		{
			return MemoryMarshal.CreateSpan(ref Unsafe.As<T, byte>(ref reference), Unsafe.SizeOf<T>());
		}

		/// <summary>
		/// Creates a read-only byte span over the referenced value.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ReadOnlySpan<byte> AsReadOnlySpan()
		{
			return MemoryMarshal.CreateReadOnlySpan(ref Unsafe.As<T, byte>(ref reference), Unsafe.SizeOf<T>());
		}
	}

	extension(ref byte reference)
	{
		/// <summary>
		/// Reinterprets the byte reference as a reference to <typeparamref name="T" />.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref T As<T>()
		{
			return ref Unsafe.As<byte, T>(ref reference);
		}

		/// <summary>
		/// Reinterprets the byte reference as a <see cref="VectorBuffer16" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer16 AsVectorBuffer16()
		{
			return ref As<VectorBuffer16>(ref reference);
		}

		/// <summary>
		/// Reinterprets the byte reference as a <see cref="VectorBuffer32" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer32 AsVectorBuffer32()
		{
			return ref As<VectorBuffer32>(ref reference);
		}

		/// <summary>
		/// Reinterprets the byte reference as a <see cref="VectorBuffer64" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer64 AsVectorBuffer64()
		{
			return ref As<VectorBuffer64>(ref reference);
		}

		/// <summary>
		/// Reinterprets the byte reference as a <see cref="VectorBuffer128" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer128 AsVectorBuffer128()
		{
			return ref As<VectorBuffer128>(ref reference);
		}

		/// <summary>
		/// Reinterprets the byte reference as a <see cref="VectorBuffer256" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer256 AsVectorBuffer256()
		{
			return ref As<VectorBuffer256>(ref reference);
		}

		/// <summary>
		/// Reinterprets the byte reference as a <see cref="VectorBuffer512" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer512 AsVectorBuffer512()
		{
			return ref As<VectorBuffer512>(ref reference);
		}

		/// <summary>
		/// Reinterprets the byte reference as a <see cref="VectorBuffer1024" /> reference.
		/// </summary>
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

		/// <summary>
		/// Reinterprets a reference to the first element as a <typeparamref name="TTo" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref TTo As<TTo>()
		{
			return ref Unsafe.As<T, TTo>(ref GetReference(span));
		}

		/// <summary>
		/// Reinterprets a reference to the first element as a <see cref="VectorBuffer16" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer16 AsVectorBuffer16()
		{
			return ref As<T, VectorBuffer16>(span);
		}

		/// <summary>
		/// Reinterprets a reference to the first element as a <see cref="VectorBuffer32" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer32 AsVectorBuffer32()
		{
			return ref As<T, VectorBuffer32>(span);
		}

		/// <summary>
		/// Reinterprets a reference to the first element as a <see cref="VectorBuffer64" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer64 AsVectorBuffer64()
		{
			return ref As<T, VectorBuffer64>(span);
		}

		/// <summary>
		/// Reinterprets a reference to the first element as a <see cref="VectorBuffer128" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer128 AsVectorBuffer128()
		{
			return ref As<T, VectorBuffer128>(span);
		}

		/// <summary>
		/// Reinterprets a reference to the first element as a <see cref="VectorBuffer256" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer256 AsVectorBuffer256()
		{
			return ref As<T, VectorBuffer256>(span);
		}

		/// <summary>
		/// Reinterprets a reference to the first element as a <see cref="VectorBuffer512" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer512 AsVectorBuffer512()
		{
			return ref As<T, VectorBuffer512>(span);
		}

		/// <summary>
		/// Reinterprets a reference to the first element as a <see cref="VectorBuffer1024" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer1024 AsVectorBuffer1024()
		{
			return ref As<T, VectorBuffer1024>(span);
		}
	}
}
