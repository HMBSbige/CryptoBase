using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures;
using CryptoBase.X509;

namespace CryptoBase.Tests.X509;

// An importer of public keys for TrustAnchorCertificateValidator that counts the keys that it imports, their verifications and their disposals, over CryptoBase's SignatureKey and, for RSA, PlatformRsaKey.
internal sealed class KeyLog
{
	private readonly Func<ReadOnlySpan<byte>, ISignatureKey> _import;
	private int _imports;
	private int _verifications;
	private int _disposals;

	public KeyLog(bool importsRsa = false)
	{
		_import = importsRsa ? ImportWithRsa : SignatureKey.ImportSubjectPublicKeyInfo;
	}

	public int Imports => Volatile.Read(ref _imports);

	public int Verifications => Volatile.Read(ref _verifications);

	public int Disposals => Volatile.Read(ref _disposals);

	// Runs on each verification, such as to cancel a validation.
	public Action? OnVerify { get; set; }

	public ISignatureKey Import(ReadOnlySpan<byte> subjectPublicKeyInfo)
	{
		ISignatureKey key = _import(subjectPublicKeyInfo);
		Interlocked.Increment(ref _imports);
		return new TrackingKey(key, this);
	}

	private void CountVerification()
	{
		Interlocked.Increment(ref _verifications);
		OnVerify?.Invoke();
	}

	private void CountDisposal()
	{
		Interlocked.Increment(ref _disposals);
	}

	private static ISignatureKey ImportWithRsa(ReadOnlySpan<byte> subjectPublicKeyInfo)
	{
		try
		{
			return SignatureKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);
		}
		catch (NotSupportedException)
		{
			return PlatformRsaKey.ImportSubjectPublicKeyInfo(subjectPublicKeyInfo);
		}
	}

	private sealed class TrackingKey(ISignatureKey inner, KeyLog log) : ISignatureKey
	{
		public bool HasPrivateKey => inner.HasPrivateKey;

		public int SubjectPublicKeyInfoLength => inner.SubjectPublicKeyInfoLength;

		public int Pkcs8PrivateKeyLength => inner.Pkcs8PrivateKeyLength;

		public bool Supports(SignatureAlgorithm algorithm)
		{
			return inner.Supports(algorithm);
		}

		public int GetMaxSignatureLength(SignatureAlgorithm algorithm)
		{
			return inner.GetMaxSignatureLength(algorithm);
		}

		public int Sign(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, Span<byte> destination)
		{
			return inner.Sign(algorithm, message, destination);
		}

		public bool Verify(SignatureAlgorithm algorithm, ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
		{
			log.CountVerification();
			return inner.Verify(algorithm, message, signature);
		}

		public int ExportSubjectPublicKeyInfo(Span<byte> destination)
		{
			return inner.ExportSubjectPublicKeyInfo(destination);
		}

		public int ExportPkcs8PrivateKey(Span<byte> destination)
		{
			return inner.ExportPkcs8PrivateKey(destination);
		}

		public void Dispose()
		{
			log.CountDisposal();
			inner.Dispose();
		}
	}
}
