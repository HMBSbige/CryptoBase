using System.Numerics;

namespace CryptoBase.Tests.EllipticCurves;

internal abstract class KeyCase
{
	internal abstract bool HasPrivateKey { get; }

	internal abstract bool HasPublicKey { get; }

	internal abstract BigInteger PrivateScalar { get; }

	internal abstract CurvePoint PublicPoint { get; }

	internal abstract int PrivateKeyLength { get; }

	internal abstract int PublicKeyLength { get; }

	internal abstract int SharedSecretLength { get; }

	internal abstract void GenerateKey();

	internal abstract void GenerateKey(Action<Span<byte>> fill);

	internal abstract bool TryImportPrivateKey(byte[] source);

	internal abstract bool TryImportPublicKey(byte[] source);

	internal abstract int ExportPrivateKey(byte[] destination);

	internal abstract int ExportPublicKey(byte[] destination);

	internal abstract bool TryDeriveSharedSecret(byte[] peerPublicKey, byte[] destination);

	internal abstract void Clear();

	internal abstract byte[] Storage();

	internal byte[] ExportPrivateKey()
	{
		byte[] destination = new byte[PrivateKeyLength];
		_ = ExportPrivateKey(destination);
		return destination;
	}

	internal byte[] ExportPublicKey()
	{
		byte[] destination = new byte[PublicKeyLength];
		_ = ExportPublicKey(destination);
		return destination;
	}

	// The secret, or null where TryDeriveSharedSecret fails.
	internal byte[]? DeriveSharedSecret(byte[] peerPublicKey)
	{
		byte[] destination = new byte[SharedSecretLength];
		return TryDeriveSharedSecret(peerPublicKey, destination) ? destination : null;
	}
}
