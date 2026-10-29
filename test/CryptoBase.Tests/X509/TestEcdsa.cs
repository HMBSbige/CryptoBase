using System.Security.Cryptography;

namespace CryptoBase.Tests.X509;

// An ECDsa that reports any SubjectPublicKeyInfo, so that keys the platform need not support reach PlatformEcdsaKey on every platform. It holds no key, so it neither signs nor verifies.
internal sealed class TestEcdsa(byte[] subjectPublicKeyInfo) : ECDsa
{
	public bool IsDisposed { get; private set; }

	public override byte[] SignHash(byte[] hash)
	{
		throw new NotSupportedException();
	}

	public override bool VerifyHash(byte[] hash, byte[] signature)
	{
		throw new NotSupportedException();
	}

	public override byte[] ExportSubjectPublicKeyInfo()
	{
		return subjectPublicKeyInfo.ToArray();
	}

	protected override void Dispose(bool disposing)
	{
		if (disposing)
		{
			IsDisposed = true;
		}

		base.Dispose(disposing);
	}
}
