using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.EllipticCurves;

// The private key d is a plain value in [1, n − 1]. Keep a key in one writable location and do not copy it: a copy keeps d where Clear cannot reach it.
internal struct EcKey<TCurve, TField, TOrder>
	where TCurve : struct, IEcCurve
	where TField : unmanaged, IMontgomeryModulus
	where TOrder : unmanaged, IMontgomeryModulus
{
	private FieldElement<TOrder> _privateKey;
	private AffinePoint<TField> _publicKey;

	internal static int PrivateKeyLength => TOrder.ByteLength;

	internal static int PublicKeyLength => EcGroup<TCurve, TField, TOrder>.EncodedLength;

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

	// Only the retry after a candidate outside [1, n − 1] branches. If fill throws, the key stays as it was.
	[SkipLocalsInit]
	internal void GenerateKey(Action<Span<byte>> fill)
	{
		using CryptoBuffer<byte> buffer = new(stackalloc byte[PrivateKeyLength]);
		Span<byte> candidate = buffer.Span;
		Unsafe.SkipInit(out FieldElement<TOrder> privateKey);

		try
		{
			do
			{
				fill(candidate);
				candidate[0] &= (byte)(0xFF >> 8 * TOrder.ByteLength - TOrder.BitLength);
			}
			while (!FieldElement<TOrder>.TryImportNonzero(candidate, out privateKey));

			SetKey(in privateKey);
		}
		finally
		{
			privateKey.ZeroMemory();
		}
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

		if (!EcGroup<TCurve, TField, TOrder>.TryDecode(source, out _publicKey))
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

		EcGroup<TCurve, TField, TOrder>.Encode(in _publicKey, destination.Slice(0, PublicKeyLength));
		return PublicKeyLength;
	}

	internal readonly bool TryDeriveSharedSecret(ReadOnlySpan<byte> peerPublicKey, Span<byte> destination)
	{
		if (!HasPrivateKey)
		{
			ThrowHelper.ThrowMissingKey("private key");
		}

		ArgumentOutOfRangeException.ThrowIfLessThan(destination.Length, SharedSecretLength, nameof(destination));

		if (!EcGroup<TCurve, TField, TOrder>.TryDecode(peerPublicKey, out AffinePoint<TField> peer))
		{
			return false;
		}

		return EcGroup<TCurve, TField, TOrder>.TryMultiplyExportX(in peer, in _privateKey, destination.Slice(0, SharedSecretLength));
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
		EcGroup<TCurve, TField, TOrder>.MultiplyBaseToAffine(in privateKey, out AffinePoint<TField> publicKey);
		_privateKey = privateKey;
		_publicKey = publicKey;
		HasPrivateKey = true;
		HasPublicKey = true;
	}
}
