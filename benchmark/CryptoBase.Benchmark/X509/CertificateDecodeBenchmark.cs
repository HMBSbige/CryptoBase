using BenchmarkDotNet.Attributes;
using CryptoBase.X509;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace CryptoBase.Benchmark.X509;

[MemoryDiagnoser]
public class CertificateDecodeBenchmark
{
	private byte[] _encoded = [];

	[GlobalSetup]
	public void Setup()
	{
		using ECDsa key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
		CertificateRequest request = new("CN=www.example.com, O=Example Corp, C=US", key, HashAlgorithmName.SHA256);
		SubjectAlternativeNameBuilder names = new();
		names.AddDnsName("www.example.com");
		names.AddDnsName("example.com");
		request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
		request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
		request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));
		request.CertificateExtensions.Add(names.Build());
		request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
		request.CertificateExtensions.Add(new X509AuthorityInformationAccessExtension(["http://ocsp.example.org/"], ["http://certs.example.org/ca.cer"]));
		request.CertificateExtensions.Add(CertificateRevocationListBuilder.BuildCrlDistributionPointExtension(["http://crl.example.org/ca.crl"]));

		using X509Certificate2 certificate = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
		_encoded = certificate.RawData;
	}

	[Benchmark]
	public Certificate Decode()
	{
		return Certificate.Decode(_encoded);
	}

	[Benchmark]
	public int? DecodeAndGetSubjectAlternativeName()
	{
		return Certificate.Decode(_encoded).GetSubjectAlternativeName()?.DnsNames.Count;
	}
}
