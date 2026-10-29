using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.EllipticCurves;

// The private key d is a plain value in [1, n − 1]. Keep a key in one writable location and do not copy it: a copy keeps d where Clear cannot reach it.
internal struct ECKey<TCurve, TField, TOrder>
	where TCurve : struct, IECCurve
	where TField : unmanaged, IECField<TField>
	where TOrder : unmanaged, IMontgomeryModulus
{
	private FieldElement<TOrder> _privateKey;
	private AffinePoint<TField> _publicKey;

	internal static int PrivateKeyLength => TOrder.ByteLength;

	internal static int PublicKeyLength => ECGroup<TCurve, TField, TOrder>.EncodedLength;

	internal static int SharedSecretLength => TField.ByteLength;

	internal bool HasPrivateKey { readonly get; private set; }

	// Set whenever HasPrivateKey is.
	internal bool HasPublicKey { readonly get; private set; }

	[UnscopedRef]
	internal readonly ref readonly FieldElement<TOrder> PrivateScalar
	{
		get
		{
			Debug.Assert(HasPrivateKey);

			return ref _privateKey;
		}
	}

	[UnscopedRef]
	internal readonly ref readonly AffinePoint<TField> PublicPoint
	{
		get
		{
			Debug.Assert(HasPublicKey);

			return ref _publicKey;
		}
	}

	internal void GenerateKey()
	{
		GenerateKey(SystemRandom.Fill);
	}

	// If fill throws, the key stays as it was.
	[SkipLocalsInit]
	internal void GenerateKey(Action<Span<byte>> fill)
	{
		Unsafe.SkipInit(out FieldElement<TOrder> privateKey);

		try
		{
			GeneratePrivateScalar(fill, out privateKey);
			SetKey(in privateKey);
		}
		finally
		{
			privateKey.ZeroMemory();
		}
	}

	// Sets result to a d in [1, n − 1] drawn from fill. Only the retry after a candidate outside that range branches.
	[SkipLocalsInit]
	internal static void GeneratePrivateScalar(Action<Span<byte>> fill, out FieldElement<TOrder> result)
	{
		using CryptoBuffer<byte> buffer = new(stackalloc byte[PrivateKeyLength]);
		Span<byte> candidate = buffer.Span;

		do
		{
			fill(candidate);
			candidate[0] &= (byte)(0xFF >> 8 * TOrder.ByteLength - TOrder.BitLength);
		}
		while (!FieldElement<TOrder>.TryImportNonzero(candidate, out result));
	}

	internal bool TryImportPrivateKey(ReadOnlySpan<byte> source)
	{
		bool imported = FieldElement<TOrder>.TryImportNonzero(source, out FieldElement<TOrder> privateKey);

		if (imported)
		{
			SetKey(in privateKey);
		}
		else
		{
			Clear();
		}

		privateKey.ZeroMemory();
		return imported;
	}

	internal bool TryImportPublicKey(ReadOnlySpan<byte> source)
	{
		Clear();

		if (!ECGroup<TCurve, TField, TOrder>.TryDecode(source, out _publicKey))
		{
			return false;
		}

		HasPublicKey = true;
		return true;
	}

	internal readonly int ExportPrivateKey(Span<byte> destination)
	{
		if (!HasPrivateKey)
		{
			ThrowHelper.ThrowMissingKey("private key");
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, PrivateKeyLength, nameof(destination));

		FieldElement<TOrder>.Export(in _privateKey, destination.Slice(0, PrivateKeyLength));
		return PrivateKeyLength;
	}

	internal readonly int ExportPublicKey(Span<byte> destination)
	{
		if (!HasPublicKey)
		{
			ThrowHelper.ThrowMissingKey("public key");
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, PublicKeyLength, nameof(destination));

		ECGroup<TCurve, TField, TOrder>.Encode(in _publicKey, destination.Slice(0, PublicKeyLength));
		return PublicKeyLength;
	}

	internal readonly bool TryDeriveSharedSecret(ReadOnlySpan<byte> peerPublicKey, Span<byte> destination)
	{
		if (!HasPrivateKey)
		{
			ThrowHelper.ThrowMissingKey("private key");
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, SharedSecretLength, nameof(destination));

		if (!ECGroup<TCurve, TField, TOrder>.TryDecode(peerPublicKey, out AffinePoint<TField> peer))
		{
			return false;
		}

		return ECGroup<TCurve, TField, TOrder>.TryMultiplyExportX(in peer, in _privateKey, destination.Slice(0, SharedSecretLength));
	}

	internal void Clear()
	{
		_privateKey.ZeroMemory();
		_publicKey.ZeroMemory();
		HasPrivateKey = false;
		HasPublicKey = false;
	}

	private void SetKey(in FieldElement<TOrder> privateKey)
	{
		ECGroup<TCurve, TField, TOrder>.MultiplyBaseToAffine(in privateKey, out AffinePoint<TField> publicKey);
		_privateKey = privateKey;
		_publicKey = publicKey;
		HasPrivateKey = true;
		HasPublicKey = true;
	}
}
