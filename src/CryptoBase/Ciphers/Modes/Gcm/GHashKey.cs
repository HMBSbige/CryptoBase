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
		return _fourBlock ?? InitializeFourBlock();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal GHashKeyTable<GHashVector128PrecomputedKey> GetVector128()
	{
		return _vector128 ?? InitializeVector128();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal GHashKeyTable<GHashVector256PrecomputedKey> GetVector256()
	{
		return _vector256 ?? InitializeVector256();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal GHashKeyTable<GHashVector512PrecomputedKey> GetVector512()
	{
		return _vector512 ?? InitializeVector512();
	}

	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	internal GHashKeyTable<GHashArmPrecomputedKey> GetArm()
	{
		return _arm ?? InitializeArm();
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private GHashKeyTable<GHashArmPrecomputedKey> InitializeArm()
	{
		GHashKeyTable<GHashArmPrecomputedKey> table = new();
		table.Value.Initialize(AdvSimd.Arm64.ReverseElementBits(Value));
		return _arm = table;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private GHashKeyTable<GHashFourBlockPrecomputedKey> InitializeFourBlock()
	{
		GHashKeyTable<GHashFourBlockPrecomputedKey> table = new();
		table.Value.Initialize(Value.ReverseEndianness128());
		return _fourBlock = table;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private GHashKeyTable<GHashVector128PrecomputedKey> InitializeVector128()
	{
		GHashKeyTable<GHashVector128PrecomputedKey> table = new();
		table.Value.Initialize(Value.ReverseEndianness128());
		return _vector128 = table;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private GHashKeyTable<GHashVector256PrecomputedKey> InitializeVector256()
	{
		GHashKeyTable<GHashVector256PrecomputedKey> table = new();
		table.Value.Initialize(Value.ReverseEndianness128());
		return _vector256 = table;
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private GHashKeyTable<GHashVector512PrecomputedKey> InitializeVector512()
	{
		GHashKeyTable<GHashVector512PrecomputedKey> table = new();
		table.Value.Initialize(Value.ReverseEndianness128());
		return _vector512 = table;
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
