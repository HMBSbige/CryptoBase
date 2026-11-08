using BenchmarkDotNet.Attributes;
using CryptoBase.X509;
using System.Formats.Asn1;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.X509;

[MemoryDiagnoser]
public class CertificateRevocationListBenchmark
{
	private byte[] _encoded = [];
	private byte[] _present = [];
	private byte[] _absent = [];
	private CertificateRevocationList _list = null!;

	[Params(1_000, 100_000)]
	public int Entries { get; set; }

	[GlobalSetup]
	public void Setup()
	{
		byte[][] serialNumbers = new byte[Entries][];

		for (int i = 0; i < serialNumbers.Length; ++i)
		{
			serialNumbers[i] = RandomNumberGenerator.GetBytes(16);
			serialNumbers[i][0] = (byte)(serialNumbers[i][0] % 0x7F + 1);
		}

		_encoded = Encode(serialNumbers);
		_present = serialNumbers[Entries / 2];
		_absent = RandomNumberGenerator.GetBytes(16);
		_absent[0] |= 0x01;
		_list = CertificateRevocationList.Decode(_encoded);
	}

	[Benchmark]
	public CertificateRevocationList Decode()
	{
		return CertificateRevocationList.Decode(_encoded);
	}

	[Benchmark]
	public bool TryGetPresentEntry()
	{
		return _list.TryGetEntry(_present, out _);
	}

	[Benchmark]
	public bool TryGetAbsentEntry()
	{
		return _list.TryGetEntry(_absent, out _);
	}

	// The signature is not checked, so it is empty.
	private static byte[] Encode(byte[][] serialNumbers)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);
		DateTimeOffset now = DateTimeOffset.UtcNow;

		using (writer.PushSequence())
		{
			using (writer.PushSequence())
			{
				writer.WriteInteger(1);
				WriteAlgorithm(writer);

				using (writer.PushSequence())
				{
				}

				writer.WriteUtcTime(now);
				writer.WriteUtcTime(now.AddDays(7));

				using (writer.PushSequence())
				{
					for (int i = 0; i < serialNumbers.Length; ++i)
					{
						using (writer.PushSequence())
						{
							writer.WriteIntegerUnsigned(serialNumbers[i]);
							writer.WriteUtcTime(now.AddSeconds(-i));

							if ((i & 1) is 0)
							{
								using (writer.PushSequence())
								using (writer.PushSequence())
								{
									writer.WriteObjectIdentifier("2.5.29.21");
									writer.WriteOctetString([0x0A, 0x01, 0x01]);
								}
							}
						}
					}
				}
			}

			WriteAlgorithm(writer);
			writer.WriteBitString(new byte[64]);
		}

		return writer.Encode();
	}

	private static void WriteAlgorithm(AsnWriter writer)
	{
		using (writer.PushSequence())
		{
			writer.WriteObjectIdentifier("1.2.840.10045.4.3.2");
		}
	}
}
