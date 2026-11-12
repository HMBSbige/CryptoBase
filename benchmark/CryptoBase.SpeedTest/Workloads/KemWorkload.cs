namespace CryptoBase.SpeedTest.Workloads;

internal enum KemOperation
{
	/// <summary>Generates a key pair and exports its encapsulation key.</summary>
	KeyGen,

	/// <summary>Encapsulates to an imported encapsulation key.</summary>
	Encapsulate,

	Decapsulate
}

internal sealed class KemWorkload<T> : Workload where T : class, IKem<T>
{
	private readonly KemOperation _operation;
	private readonly T _keyPair = T.GenerateKey();
	private readonly T _encapsulationKey;
	private readonly byte[] _publicKey = new byte[T.EncapsulationKeyLength];
	private readonly byte[] _ciphertext = new byte[T.CiphertextLength];
	private readonly byte[] _sharedSecret = new byte[T.SharedSecretLength];
	private readonly byte[] _output = new byte[T.SharedSecretLength];
	private readonly byte[] _generatedPublicKey = new byte[T.EncapsulationKeyLength];

	public KemWorkload(KemOperation operation)
	{
		_operation = operation;
		_keyPair.ExportEncapsulationKey(_publicKey);
		_encapsulationKey = T.ImportEncapsulationKey(_publicKey);
		_encapsulationKey.Encapsulate(_ciphertext, _sharedSecret);
	}

	public override void Verify()
	{
		SelfTestException.ThrowIfFalse(_keyPair.TryDecapsulate(_ciphertext, _output), "Decapsulation rejected a valid ciphertext.");
		SelfTestException.ThrowIfNotEqual(_sharedSecret, _output, "Decapsulation recovered a different shared secret.");

		byte[] ciphertext = new byte[T.CiphertextLength];
		byte[] sharedSecret = new byte[T.SharedSecretLength];
		_encapsulationKey.Encapsulate(ciphertext, sharedSecret);
		SelfTestException.ThrowIfFalse(!sharedSecret.AsSpan().SequenceEqual(_sharedSecret), "Two encapsulations gave the same shared secret.");

		using T other = T.GenerateKey();
		byte[] otherPublicKey = new byte[T.EncapsulationKeyLength];
		other.ExportEncapsulationKey(otherPublicKey);
		SelfTestException.ThrowIfFalse(!otherPublicKey.AsSpan().SequenceEqual(_publicKey), "Two generated key pairs are the same.");
	}

	public override void Run(long iterations)
	{
		switch (_operation)
		{
			case KemOperation.KeyGen:
			{
				GenerateKeys(iterations);
				break;
			}
			case KemOperation.Encapsulate:
			{
				Encapsulate(iterations);
				break;
			}
			case KemOperation.Decapsulate:
			{
				Decapsulate(iterations);
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
		_keyPair.Dispose();
		_encapsulationKey.Dispose();
	}

	private void GenerateKeys(long iterations)
	{
		Span<byte> publicKey = _generatedPublicKey;

		for (long i = 0; i < iterations; ++i)
		{
			using T key = T.GenerateKey();
			key.ExportEncapsulationKey(publicKey);
		}
	}

	private void Encapsulate(long iterations)
	{
		T key = _encapsulationKey;
		Span<byte> ciphertext = _ciphertext;
		Span<byte> sharedSecret = _sharedSecret;

		for (long i = 0; i < iterations; ++i)
		{
			key.Encapsulate(ciphertext, sharedSecret);
		}
	}

	private void Decapsulate(long iterations)
	{
		T key = _keyPair;
		ReadOnlySpan<byte> ciphertext = _ciphertext;
		Span<byte> sharedSecret = _output;

		for (long i = 0; i < iterations; ++i)
		{
			if (!key.TryDecapsulate(ciphertext, sharedSecret))
			{
				SelfTestException.Throw("Decapsulation rejected a valid ciphertext.");
			}
		}
	}
}
