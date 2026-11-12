using CryptoBase.SM9;

namespace CryptoBase.SpeedTest.Workloads;

internal sealed class SM9SignatureWorkload : Workload
{
	private const int MessageLength = 32;

	private static readonly byte[] SignerId = "alice@example.com"u8.ToArray();

	private readonly bool _verify;
	private readonly SM9SignatureKey _signer;
	private readonly SM9SignatureMasterKey _verifier;
	private readonly byte[] _message = TestData.Random(MessageLength);
	private readonly byte[] _signature = new byte[SM9SignatureKey.SignatureLength];
	private readonly byte[] _newSignature = new byte[SM9SignatureKey.SignatureLength];

	public SM9SignatureWorkload(bool verify)
	{
		_verify = verify;

		using SM9SignatureMasterKey master = SM9SignatureMasterKey.GenerateKey();
		byte[] masterPublicKey = new byte[SM9SignatureMasterKey.PublicKeyLength];
		master.ExportPublicKey(masterPublicKey);

		_signer = master.ExtractKey(SignerId);
		_verifier = SM9SignatureMasterKey.ImportPublicKey(masterPublicKey);
		_signer.Sign(_message, _signature);
	}

	public override void Verify()
	{
		SelfTestException.ThrowIfFalse(_verifier.Verify(_message, _signature, SignerId), "Verification rejected a valid signature.");

		byte[] tampered = [.. _signature];
		tampered[^1] ^= 1;
		SelfTestException.ThrowIfFalse(!_verifier.Verify(_message, tampered, SignerId), "Verification accepted a tampered signature.");
		SelfTestException.ThrowIfFalse(!_verifier.Verify(_message, _signature, "bob@example.com"u8), "Verification accepted the signature for another ID.");
	}

	public override void Run(long iterations)
	{
		if (_verify)
		{
			VerifySignatures(iterations);
		}
		else
		{
			Sign(iterations);
		}
	}

	public override void Dispose()
	{
		_signer.Dispose();
		_verifier.Dispose();
	}

	private void Sign(long iterations)
	{
		SM9SignatureKey key = _signer;
		ReadOnlySpan<byte> message = _message;
		Span<byte> signature = _newSignature;

		for (long i = 0; i < iterations; ++i)
		{
			key.Sign(message, signature);
		}
	}

	private void VerifySignatures(long iterations)
	{
		SM9SignatureMasterKey key = _verifier;
		ReadOnlySpan<byte> message = _message;
		ReadOnlySpan<byte> signature = _signature;
		ReadOnlySpan<byte> id = SignerId;

		for (long i = 0; i < iterations; ++i)
		{
			if (!key.Verify(message, signature, id))
			{
				SelfTestException.Throw("Verification rejected a valid signature.");
			}
		}
	}
}
