using BenchmarkDotNet.Attributes;
using CryptoBase.Hpke;

namespace CryptoBase.Benchmark.Hpke;

public class DhKemX25519Benchmark : DhKemBenchmark<DhKemX25519>;

public class DhKemX448Benchmark : DhKemBenchmark<DhKemX448>;

public class DhKemP256Benchmark : DhKemBenchmark<DhKemP256>;

public class DhKemP384Benchmark : DhKemBenchmark<DhKemP384>;

public class DhKemP521Benchmark : DhKemBenchmark<DhKemP521>;

// The KEM operations alone, without the HPKE key schedule.
[MemoryDiagnoser]
public abstract class DhKemBenchmark<TKem> where TKem : class, IHpkeAuthKem<TKem>
{
	private readonly byte[] _encapsulationKey = new byte[TKem.EncapsulationKeyLength];
	private readonly byte[] _decapsulationKey = new byte[TKem.DecapsulationKeyLength];
	private readonly byte[] _ciphertext = new byte[TKem.CiphertextLength];
	private readonly byte[] _authCiphertext = new byte[TKem.CiphertextLength];
	private readonly byte[] _output = new byte[TKem.CiphertextLength];
	private readonly byte[] _sharedSecret = new byte[TKem.SharedSecretLength];
	private TKem _recipient = null!;
	private TKem _recipientPublicKey = null!;
	private TKem _sender = null!;
	private TKem _senderPublicKey = null!;

	[GlobalSetup]
	public void Setup()
	{
		_recipient = TKem.GenerateKey();
		_recipient.ExportEncapsulationKey(_encapsulationKey);
		_recipient.ExportDecapsulationKey(_decapsulationKey);
		_recipientPublicKey = TKem.ImportEncapsulationKey(_encapsulationKey);
		_sender = TKem.GenerateKey();
		byte[] senderEncapsulationKey = new byte[TKem.EncapsulationKeyLength];
		_sender.ExportEncapsulationKey(senderEncapsulationKey);
		_senderPublicKey = TKem.ImportEncapsulationKey(senderEncapsulationKey);

		byte[] expected = new byte[TKem.SharedSecretLength];
		_recipientPublicKey.Encapsulate(_ciphertext, expected);

		if (!_recipient.TryDecapsulate(_ciphertext, _sharedSecret) || !_sharedSecret.AsSpan().SequenceEqual(expected))
		{
			throw new InvalidOperationException("The ciphertext did not decapsulate to the shared secret.");
		}

		_recipientPublicKey.AuthEncapsulate(_sender, _authCiphertext, expected);

		if (!_recipient.TryAuthDecapsulate(_authCiphertext, _senderPublicKey, _sharedSecret) || !_sharedSecret.AsSpan().SequenceEqual(expected))
		{
			throw new InvalidOperationException("The authenticated ciphertext did not decapsulate to the shared secret.");
		}
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_recipient.Dispose();
		_recipientPublicKey.Dispose();
		_sender.Dispose();
		_senderPublicKey.Dispose();
	}

	[Benchmark]
	public void GenerateKey()
	{
		using TKem kem = TKem.GenerateKey();
	}

	[Benchmark]
	public void ImportDecapsulationKey()
	{
		using TKem kem = TKem.ImportDecapsulationKey(_decapsulationKey);
	}

	[Benchmark]
	public void ImportEncapsulationKey()
	{
		using TKem kem = TKem.ImportEncapsulationKey(_encapsulationKey);
	}

	[Benchmark]
	public void Encapsulate()
	{
		_recipientPublicKey.Encapsulate(_output, _sharedSecret);
	}

	[Benchmark]
	public bool Decapsulate()
	{
		return _recipient.TryDecapsulate(_ciphertext, _sharedSecret);
	}

	[Benchmark]
	public void AuthEncapsulate()
	{
		_recipientPublicKey.AuthEncapsulate(_sender, _output, _sharedSecret);
	}

	[Benchmark]
	public bool AuthDecapsulate()
	{
		return _recipient.TryAuthDecapsulate(_authCiphertext, _senderPublicKey, _sharedSecret);
	}
}
