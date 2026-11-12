namespace CryptoBase.SpeedTest.Workloads;

internal enum KeyAgreementOperation
{
	/// <summary>Generates a key pair and exports its public key.</summary>
	KeyGen,

	/// <summary>Derives the shared secret from the encoded public key of the peer.</summary>
	Derive
}

internal sealed class KeyAgreementWorkload<T> : Workload where T : class, IKeyAgreement<T>
{
	private readonly KeyAgreementOperation _operation;
	private readonly T _alice = T.GenerateKey();
	private readonly T _bob = T.GenerateKey();
	private readonly byte[] _alicePublicKey = new byte[T.PublicKeyLength];
	private readonly byte[] _bobPublicKey = new byte[T.PublicKeyLength];
	private readonly byte[] _sharedSecret = new byte[T.SharedSecretLength];
	private readonly byte[] _generatedPublicKey = new byte[T.PublicKeyLength];

	public KeyAgreementWorkload(KeyAgreementOperation operation)
	{
		_operation = operation;
		_alice.ExportPublicKey(_alicePublicKey);
		_bob.ExportPublicKey(_bobPublicKey);
	}

	public override void Verify()
	{
		byte[] bobSecret = new byte[T.SharedSecretLength];
		SelfTestException.ThrowIfFalse(_alice.TryDeriveSharedSecret(_bobPublicKey, _sharedSecret), "Derivation rejected a valid public key.");
		SelfTestException.ThrowIfFalse(_bob.TryDeriveSharedSecret(_alicePublicKey, bobSecret), "Derivation rejected a valid public key.");
		SelfTestException.ThrowIfNotEqual(_sharedSecret, bobSecret, "The two parties derived different shared secrets.");
		SelfTestException.ThrowIfFalse(!_alicePublicKey.AsSpan().SequenceEqual(_bobPublicKey), "Two generated key pairs are the same.");
	}

	public override void Run(long iterations)
	{
		switch (_operation)
		{
			case KeyAgreementOperation.KeyGen:
			{
				GenerateKeys(iterations);
				break;
			}
			case KeyAgreementOperation.Derive:
			{
				Derive(iterations);
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
		_alice.Dispose();
		_bob.Dispose();
	}

	private void GenerateKeys(long iterations)
	{
		Span<byte> publicKey = _generatedPublicKey;

		for (long i = 0; i < iterations; ++i)
		{
			using T key = T.GenerateKey();
			key.ExportPublicKey(publicKey);
		}
	}

	private void Derive(long iterations)
	{
		T key = _alice;
		ReadOnlySpan<byte> peerPublicKey = _bobPublicKey;
		Span<byte> sharedSecret = _sharedSecret;

		for (long i = 0; i < iterations; ++i)
		{
			if (!key.TryDeriveSharedSecret(peerPublicKey, sharedSecret))
			{
				SelfTestException.Throw("Derivation rejected a valid public key.");
			}
		}
	}
}
