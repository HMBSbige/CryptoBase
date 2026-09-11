namespace CryptoBase.Abstractions.Internal.Extensions;

/// <summary>
/// Provides low-level reference reinterpretation extensions.
/// </summary>
internal static class SpanReinterpretExtensions
{
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
			return ref reference.As<VectorBuffer16>();
		}

		/// <summary>
		/// Reinterprets the byte reference as a <see cref="VectorBuffer32" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer32 AsVectorBuffer32()
		{
			return ref reference.As<VectorBuffer32>();
		}

		/// <summary>
		/// Reinterprets the byte reference as a <see cref="VectorBuffer64" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer64 AsVectorBuffer64()
		{
			return ref reference.As<VectorBuffer64>();
		}

		/// <summary>
		/// Reinterprets the byte reference as a <see cref="VectorBuffer128" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer128 AsVectorBuffer128()
		{
			return ref reference.As<VectorBuffer128>();
		}

		/// <summary>
		/// Reinterprets the byte reference as a <see cref="VectorBuffer256" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer256 AsVectorBuffer256()
		{
			return ref reference.As<VectorBuffer256>();
		}

		/// <summary>
		/// Reinterprets the byte reference as a <see cref="VectorBuffer512" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer512 AsVectorBuffer512()
		{
			return ref reference.As<VectorBuffer512>();
		}

		/// <summary>
		/// Reinterprets the byte reference as a <see cref="VectorBuffer1024" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer1024 AsVectorBuffer1024()
		{
			return ref reference.As<VectorBuffer1024>();
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
			return ref Unsafe.As<T, TTo>(ref span.GetReference());
		}

		/// <summary>
		/// Reinterprets a reference to the first element as a <see cref="VectorBuffer16" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer16 AsVectorBuffer16()
		{
			return ref span.As<T, VectorBuffer16>();
		}

		/// <summary>
		/// Reinterprets a reference to the first element as a <see cref="VectorBuffer32" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer32 AsVectorBuffer32()
		{
			return ref span.As<T, VectorBuffer32>();
		}

		/// <summary>
		/// Reinterprets a reference to the first element as a <see cref="VectorBuffer64" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer64 AsVectorBuffer64()
		{
			return ref span.As<T, VectorBuffer64>();
		}

		/// <summary>
		/// Reinterprets a reference to the first element as a <see cref="VectorBuffer128" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer128 AsVectorBuffer128()
		{
			return ref span.As<T, VectorBuffer128>();
		}

		/// <summary>
		/// Reinterprets a reference to the first element as a <see cref="VectorBuffer256" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer256 AsVectorBuffer256()
		{
			return ref span.As<T, VectorBuffer256>();
		}

		/// <summary>
		/// Reinterprets a reference to the first element as a <see cref="VectorBuffer512" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer512 AsVectorBuffer512()
		{
			return ref span.As<T, VectorBuffer512>();
		}

		/// <summary>
		/// Reinterprets a reference to the first element as a <see cref="VectorBuffer1024" /> reference.
		/// </summary>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public ref VectorBuffer1024 AsVectorBuffer1024()
		{
			return ref span.As<T, VectorBuffer1024>();
		}
	}
}
