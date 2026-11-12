using CryptoBase.SM9;

namespace CryptoBase.SpeedTest.Workloads;

internal sealed class SM9KemWorkload : Workload
{
	private const int KeyLength = 32;

	private static readonly byte[] RecipientId = "alice@example.com"u8.ToArray();

	private readonly bool _decapsulate;
	private readonly SM9EncryptionMasterKey _sender;
	private readonly SM9EncryptionKey _recipient;
	private readonly byte[] _encapsulation = new byte[SM9EncryptionMasterKey.EncapsulationLength];
	private readonly byte[] _sharedKey = new byte[KeyLength];
	private readonly byte[] _newEncapsulation = new byte[SM9EncryptionMasterKey.EncapsulationLength];
	private readonly byte[] _output = new byte[KeyLength];

	public SM9KemWorkload(bool decapsulate)
	{
		_decapsulate = decapsulate;

		using SM9EncryptionMasterKey master = SM9EncryptionMasterKey.GenerateKey();
		byte[] masterPublicKey = new byte[SM9EncryptionMasterKey.PublicKeyLength];
		master.ExportPublicKey(masterPublicKey);

		_recipient = master.ExtractKey(RecipientId);
		_sender = SM9EncryptionMasterKey.ImportPublicKey(masterPublicKey);
		_sender.Encapsulate(_encapsulation, _sharedKey, RecipientId);
	}

	public override void Verify()
	{
		SelfTestException.ThrowIfFalse(_recipient.TryDecapsulate(_encapsulation, _output), "Decapsulation rejected a valid encapsulation.");
		SelfTestException.ThrowIfNotEqual(_sharedKey, _output, "Decapsulation recovered a different key.");

		byte[] encapsulation = new byte[SM9EncryptionMasterKey.EncapsulationLength];
		byte[] sharedKey = new byte[KeyLength];
		_sender.Encapsulate(encapsulation, sharedKey, RecipientId);
		SelfTestException.ThrowIfFalse(!sharedKey.AsSpan().SequenceEqual(_sharedKey), "Two encapsulations gave the same key.");
	}

	public override void Run(long iterations)
	{
		if (_decapsulate)
		{
			Decapsulate(iterations);
		}
		else
		{
			Encapsulate(iterations);
		}
	}

	public override void Dispose()
	{
		_sender.Dispose();
		_recipient.Dispose();
	}

	private void Encapsulate(long iterations)
	{
		SM9EncryptionMasterKey key = _sender;
		Span<byte> encapsulation = _newEncapsulation;
		Span<byte> sharedKey = _output;
		ReadOnlySpan<byte> id = RecipientId;

		for (long i = 0; i < iterations; ++i)
		{
			key.Encapsulate(encapsulation, sharedKey, id);
		}
	}

	private void Decapsulate(long iterations)
	{
		SM9EncryptionKey key = _recipient;
		ReadOnlySpan<byte> encapsulation = _encapsulation;
		Span<byte> sharedKey = _output;

		for (long i = 0; i < iterations; ++i)
		{
			if (!key.TryDecapsulate(encapsulation, sharedKey))
			{
				SelfTestException.Throw("Decapsulation rejected a valid encapsulation.");
			}
		}
	}
}
