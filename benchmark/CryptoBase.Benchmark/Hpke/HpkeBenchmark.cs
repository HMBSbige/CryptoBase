using BenchmarkDotNet.Attributes;
using CryptoBase.Hpke;

namespace CryptoBase.Benchmark.Hpke;

public class HpkeDhKemX25519SetupBenchmark() : HpkeSetupBenchmark<DhKemX25519>(HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm);

public class HpkeDhKemX25519ChaCha20Poly1305SetupBenchmark() : HpkeSetupBenchmark<DhKemX25519>(HpkeKdf.HkdfSha256, HpkeAead.ChaCha20Poly1305);

public class HpkeDhKemP256SetupBenchmark() : HpkeSetupBenchmark<DhKemP256>(HpkeKdf.HkdfSha256, HpkeAead.Aes128Gcm);

public class HpkeDhKemP384SetupBenchmark() : HpkeSetupBenchmark<DhKemP384>(HpkeKdf.HkdfSha384, HpkeAead.Aes256Gcm);

public class HpkeDhKemP521SetupBenchmark() : HpkeSetupBenchmark<DhKemP521>(HpkeKdf.HkdfSha512, HpkeAead.Aes256Gcm);

// A context setup in the base mode: one encapsulation or decapsulation, then the key schedule.
[MemoryDiagnoser]
public abstract class HpkeSetupBenchmark<TKem>(HpkeKdf kdf, HpkeAead aead) where TKem : class, IHpkeKem<TKem>
{
	private readonly byte[] _info = "HPKE benchmark"u8.ToArray();
	private readonly byte[] _enc = new byte[TKem.CiphertextLength];
	private TKem _recipient = null!;
	private TKem _recipientPublicKey = null!;

	[GlobalSetup]
	public void Setup()
	{
		_recipient = TKem.GenerateKey();
		byte[] encapsulationKey = new byte[TKem.EncapsulationKeyLength];
		_recipient.ExportEncapsulationKey(encapsulationKey);
		_recipientPublicKey = TKem.ImportEncapsulationKey(encapsulationKey);

		using HpkeSenderContext sender = HpkeSenderContext.Create(_recipientPublicKey, kdf, aead, _enc, _info);

		if (!HpkeRecipientContext.TryCreate(_recipient, kdf, aead, _enc, _info, out HpkeRecipientContext? recipient))
		{
			throw new InvalidOperationException("The recipient context was not set up.");
		}

		recipient.Dispose();
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_recipient.Dispose();
		_recipientPublicKey.Dispose();
	}

	[Benchmark]
	public void SetUpSender()
	{
		using HpkeSenderContext context = HpkeSenderContext.Create(_recipientPublicKey, kdf, aead, _enc, _info);
	}

	[Benchmark]
	public void SetUpRecipient()
	{
		_ = HpkeRecipientContext.TryCreate(_recipient, kdf, aead, _enc, _info, out HpkeRecipientContext? context);
		context?.Dispose();
	}
}

// Seal and Open on contexts set up once. Open goes back to sequence number 0 each time, as a stateless recipient would.
[MemoryDiagnoser]
public class HpkeSealOpenBenchmark
{
	private readonly byte[] _associatedData = "HPKE benchmark"u8.ToArray();
	private DhKemP256 _recipientKey = null!;
	private HpkeSenderContext _sender = null!;
	private HpkeRecipientContext _recipient = null!;
	private byte[] _plaintext = null!;
	private byte[] _ciphertext = null!;
	private byte[] _output = null!;

	[Params(HpkeAead.Aes128Gcm, HpkeAead.Aes256Gcm, HpkeAead.ChaCha20Poly1305)]
	public HpkeAead Aead { get; set; }

	[Params(64, 1024, 16384)]
	public int Length { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		_recipientKey = DhKemP256.GenerateKey();
		byte[] enc = new byte[DhKemP256.CiphertextLength];
		_sender = HpkeSenderContext.Create(_recipientKey, HpkeKdf.HkdfSha256, Aead, enc);

		if (!HpkeRecipientContext.TryCreate(_recipientKey, HpkeKdf.HkdfSha256, Aead, enc, default, out HpkeRecipientContext? recipient))
		{
			throw new InvalidOperationException("The recipient context was not set up.");
		}

		_recipient = recipient;
		_plaintext = new byte[Length];
		Random.Shared.NextBytes(_plaintext);
		_ciphertext = new byte[Length + Aead.TagSize];
		_output = new byte[Length + Aead.TagSize];
		_sender.Seal(_plaintext, _ciphertext, _associatedData);

		if (!Open() || !_output.AsSpan(0, Length).SequenceEqual(_plaintext))
		{
			throw new InvalidOperationException("The ciphertext did not open.");
		}
	}

	[GlobalCleanup]
	public void Cleanup()
	{
		_sender.Dispose();
		_recipient.Dispose();
		_recipientKey.Dispose();
	}

	[Benchmark]
	public int Seal()
	{
		return _sender.Seal(_plaintext, _output, _associatedData);
	}

	[Benchmark]
	public bool Open()
	{
		_recipient.SequenceNumber = 0;
		return _recipient.TryOpen(_ciphertext, _output, _associatedData);
	}
}
