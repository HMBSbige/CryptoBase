namespace CryptoBase.Ciphers.Modes.Gcm;

internal struct GHashKey
{
	internal Vector128<byte> Value;
	private GHashKeyTable<GHashFourBlockPrecomputedKey>? _fourBlock;
	private GHashKeyTable<GHashVector128PrecomputedKey>? _vector128;
	private GHashKeyTable<GHashVector256PrecomputedKey>? _vector256;
	private GHashKeyTable<GHashVector512PrecomputedKey>? _vector512;
	private GHashKeyTable<GHashArmPrecomputedKey>? _arm;

	internal static GHashKey Create(ReadOnlySpan<byte> key)
	{
		ArgumentOutOfRangeException.ThrowIfNotEqual(key.Length, GHash.BlockSizeInBytes, nameof(key));
		return new GHashKey { Value = Vector128.LoadUnsafe(ref MemoryMarshal.GetReference(key)) };
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal GHashKeyTable<GHashFourBlockPrecomputedKey> GetFourBlock()
	{
		return _fourBlock ?? Initialize(ref _fourBlock);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal GHashKeyTable<GHashVector128PrecomputedKey> GetVector128()
	{
		return _vector128 ?? Initialize(ref _vector128);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal GHashKeyTable<GHashVector256PrecomputedKey> GetVector256()
	{
		return _vector256 ?? Initialize(ref _vector256);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal GHashKeyTable<GHashVector512PrecomputedKey> GetVector512()
	{
		return _vector512 ?? Initialize(ref _vector512);
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal GHashKeyTable<GHashArmPrecomputedKey> GetArm()
	{
		return _arm ?? Initialize(ref _arm);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private GHashKeyTable<T> Initialize<T>(ref GHashKeyTable<T>? slot) where T : unmanaged, IGHashPrecomputedKey
	{
		GHashKeyTable<T> table = new();
		table.Value.Initialize(typeof(T) == typeof(GHashArmPrecomputedKey) ? AdvSimd.Arm64.ReverseElementBits(Value) : Value.ReverseEndianness128());
		return slot = table;
	}

	internal void Dispose()
	{
		Value.ZeroMemory();
		_fourBlock?.Dispose();
		_vector128?.Dispose();
		_vector256?.Dispose();
		_vector512?.Dispose();
		_arm?.Dispose();
		_fourBlock = null;
		_vector128 = null;
		_vector256 = null;
		_vector512 = null;
		_arm = null;
	}
}
