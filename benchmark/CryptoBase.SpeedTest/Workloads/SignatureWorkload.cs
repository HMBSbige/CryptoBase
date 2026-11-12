using CryptoBase.Abstractions.Signatures;

namespace CryptoBase.SpeedTest.Workloads;

internal enum SignatureOperation
{
	/// <summary>Creates a key pair and exports its SubjectPublicKeyInfo.</summary>
	KeyGen,

	Sign,

	/// <summary>Verifies a valid signature with an instance that holds only the public key.</summary>
	Verify
}

internal sealed class SignatureWorkload<T> : Workload where T : class, ISignatureKey<T>
{
	private const int MessageLength = 32;

	private readonly SignatureOperation _operation;
	private readonly SignatureAlgorithm _algorithm;
	private readonly Func<T> _createKey;
	private readonly T _signer;
	private readonly T _verifier;
	private readonly byte[] _message = TestData.Random(MessageLength);
	private readonly byte[] _publicKey;
	private readonly byte[] _signature;
	private readonly int _signatureLength;
	private readonly byte[] _generatedPublicKey;
	private readonly byte[] _newSignature;

	/// <param name="createKey">Creates a key pair: a new one for <see cref="SignatureOperation.KeyGen" />, or a fixed one where generating it would take long.</param>
	public SignatureWorkload(SignatureOperation operation, SignatureAlgorithm algorithm, Func<T> createKey)
	{
		_operation = operation;
		_algorithm = algorithm;
		_createKey = createKey;
		_signer = createKey();
		_publicKey = new byte[_signer.SubjectPublicKeyInfoLength];
		_signer.ExportSubjectPublicKeyInfo(_publicKey);
		_verifier = T.ImportSubjectPublicKeyInfo(_publicKey);
		_signature = new byte[_signer.GetMaxSignatureLength(algorithm)];
		_signatureLength = _signer.Sign(algorithm, _message, _signature);
		_generatedPublicKey = new byte[_publicKey.Length];
		_newSignature = new byte[_signature.Length];
	}

	public override void Verify()
	{
		ReadOnlySpan<byte> signature = _signature.AsSpan(0, _signatureLength);
		SelfTestException.ThrowIfFalse(_verifier.Verify(_algorithm, _message, signature), "Verification rejected a valid signature.");

		byte[] tampered = signature.ToArray();
		tampered[^1] ^= 1;
		SelfTestException.ThrowIfFalse(!_verifier.Verify(_algorithm, _message, tampered), "Verification accepted a tampered signature.");

		byte[] otherMessage = [.. _message];
		otherMessage[0] ^= 1;
		SelfTestException.ThrowIfFalse(!_verifier.Verify(_algorithm, otherMessage, signature), "Verification accepted the signature of another message.");

		if (_operation is SignatureOperation.KeyGen)
		{
			using T other = _createKey();
			byte[] otherPublicKey = new byte[other.SubjectPublicKeyInfoLength];
			other.ExportSubjectPublicKeyInfo(otherPublicKey);
			SelfTestException.ThrowIfFalse(!otherPublicKey.AsSpan().SequenceEqual(_publicKey), "Two generated key pairs are the same.");
		}
	}

	public override void Run(long iterations)
	{
		switch (_operation)
		{
			case SignatureOperation.KeyGen:
			{
				GenerateKeys(iterations);
				break;
			}
			case SignatureOperation.Sign:
			{
				Sign(iterations);
				break;
			}
			case SignatureOperation.Verify:
			{
				VerifySignatures(iterations);
				break;
			}
			default:
			{
				throw new UnreachableException();
			}
		}
	}

	public override void Dispose()
	{
		_signer.Dispose();
		_verifier.Dispose();
	}

	private void GenerateKeys(long iterations)
	{
		Func<T> createKey = _createKey;
		Span<byte> publicKey = _generatedPublicKey;

		for (long i = 0; i < iterations; ++i)
		{
			using T key = createKey();
			key.ExportSubjectPublicKeyInfo(publicKey);
		}
	}

	private void Sign(long iterations)
	{
		T key = _signer;
		SignatureAlgorithm algorithm = _algorithm;
		ReadOnlySpan<byte> message = _message;
		Span<byte> signature = _newSignature;

		for (long i = 0; i < iterations; ++i)
		{
			key.Sign(algorithm, message, signature);
		}
	}

	private void VerifySignatures(long iterations)
	{
		T key = _verifier;
		SignatureAlgorithm algorithm = _algorithm;
		ReadOnlySpan<byte> message = _message;
		ReadOnlySpan<byte> signature = _signature.AsSpan(0, _signatureLength);

		for (long i = 0; i < iterations; ++i)
		{
			if (!key.Verify(algorithm, message, signature))
			{
				SelfTestException.Throw("Verification rejected a valid signature.");
			}
		}
	}
}
