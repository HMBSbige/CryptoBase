using CryptoBase.Abstractions.Signatures;
using CryptoBase.Signatures.Rsa;
using System.Formats.Asn1;
using System.Numerics;
using System.Security.Cryptography;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Signatures.Rsa;

internal static class RsaTestUtils
{
	public const string RsaEncryptionOid = "1.2.840.113549.1.1.1";
	public const string RsassaPssOid = "1.2.840.113549.1.1.10";

	public static readonly SignatureAlgorithm[] Algorithms =
	[
		SignatureAlgorithm.RsaPkcs1Sha256, SignatureAlgorithm.RsaPkcs1Sha384, SignatureAlgorithm.RsaPkcs1Sha512,
		SignatureAlgorithm.RsaPssSha256, SignatureAlgorithm.RsaPssSha384, SignatureAlgorithm.RsaPssSha512
	];

	public static readonly SignatureAlgorithm[] Pkcs1Algorithms = [SignatureAlgorithm.RsaPkcs1Sha256, SignatureAlgorithm.RsaPkcs1Sha384, SignatureAlgorithm.RsaPkcs1Sha512];

	public static readonly SignatureAlgorithm[] PssAlgorithms = [SignatureAlgorithm.RsaPssSha256, SignatureAlgorithm.RsaPssSha384, SignatureAlgorithm.RsaPssSha512];

	// rsaEncryption with NULL parameters.
	public static readonly byte[] RsaEncryption = Sequence(Oid(RsaEncryptionOid), [0x05, 0x00]);

	// PKCS #8 keys with e = 65537, so that tests need not generate keys: those of 2048, 3072 and 4096 bits are from rsa_pkcs1_2048_sig_gen_test.json, rsa_pkcs1_3072_sig_gen_test.json and
	// rsa_pkcs1_4096_sig_gen_test.json of Wycheproof, and the one of 512 bits, the shortest modulus, was generated for these tests.
	private static readonly Dictionary<int, byte[]> Keys = new()
	{
		[512] = Convert.FromBase64String("MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEA6MNvTD006kpg75inlHBwmzYLnWXIQOJwtHrtgC0FyorzdG5bx5RF5DmouYgqHl9/8vnDiAFPfUKcWPZuG1Wd7QIDAQABAkAF6oe+6pRYeyT9GgZyY6w9CbHgYYimO4stTy2PszVBOVv/dSWoD9pgosE7r25ogJ0W24/cRA4KQNnX2/z8Sw9JAiEA9gNY6XoCzyTNFToAnu4oilBG9QPersY2qOUrxhYKNVkCIQDyNmR2Exb8kf1xqIm4JrinuM5IYENQykYk6Aqc6YJWtQIgcV1pg21uDfZvavCniJVGqTYE/LMj0nYUig/Q9B8D5UECIFifNDTLmU6CcBQlEXbSnB+qC7gJmLe3uuCIElIFUk49AiEA6T6QjbTQXM0w+7zPiZ9HElJc5F2iLZT4wOsASRKVKNo="),
		[2048] = Convert.FromBase64String("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCitFGgfQql+W5FVnFRNVBRSopbRi6+9xcJT6H+6CIk5jf5dG0/fK/TGHjYAyW271oXAPZZA7RpQp6J1urIhFCXtas5MYnbklEu2KdxGhJT+s0g95wV6CR/PT5C5G5IyY4lSi/pdlMToD7/jxfhoCk5eh+iao3OJvSQ7YEplhXZgUwi2mEEKOCcfZZYWUJm9cAh0PzsoI2UWhK+gt5NHs5rTAMUW100ldTtVBHrh42vBf16/D4JraDxEmQi9ZCXWhlpgW9IaYvLuhtNnK551GDY+fheeXUAXZvCLE5awPfBpF0SVppigH07mgLlpTDncwZvRT0fW0wunPeCAoP3QrnVAgMBAAECggEAdifu81Z7KicmjlIFPs0xw6cXLMud3O6BmzBqWzxmt1c8pPqI78bzxKAL+grnE59kVDpNrD0Fgj9v9HfPzshP4qx6aLFyBLOQIy4RAxDE6JnE58EJZ9tKzeBC278Z2+ALS0dB3hAgqqr/tQVMeXyfE299k6w/yMr/ZlQkLXgh6+5Re/U39ENmoP3UWuBbmQnC5swe2Sge/0OZ92yWuWIz7CmuC78NdSsjT8GXOJ9RBQqhrNAcB0w6yPvbnqi2UalZlejbStXEO2yGc+WhJufulLjf9MWvwBJZvI2naVC65vi65xX1CYWw1vZtBMb+87cAcg7s3N8XG7ex7L5yicRnwQKBgQDcQxBQ94LolPtSSCR9mMt9WLjR4k87VdBBxW5N4Iaw1bsCi9pC7rXSNNVoHlgJ1BXmoomtTPv3j5ePbDWBT1Duv/HFuApp94joHmurXdqng2nWWdFD7G8X55gTpXXPrZxWkVa5ARPi6REK2ee0ihyTSKbmUzIRkSkOo2z7OlsY8QKBgQC9GoHnl3+YmBIic64yIrWY6l+xnrTqvDgwil4yGWYDsuUA/7efW4hoFmEd68Ry+sRVRAcL6wV8lBN4poaK87egPT+YgOxH1eCJuU+95UKrqa6NcsVwiNer9bEx85CY97wWD5BTaryUkv1OBvPtcpnUuXuwNncgfZVmnxQM+8IPJQKBgQCpS1KLKPKRWZEh2RlS/9HH8h18FHnZnUeIhfsWGHDuEhi/CEcmEtvlSX6NnGUGiOCceGlhrj4sNU3EiuNFFHWcTCPEWISIlh3Aa0FOYcDh5/u9KSPTFTL+KJ+W2iIHEeWMFAGYCOAEFCdpM7sH5O+5tKmzdlaRcgUgnzPwlRXXwQKBgDrw5yqTOu8J/yUD33i6/tUxwC/xorxDfFQM3L1K01Q1z1EXY1llQ0gGKbEUyn94D/fvoy6gy24ADW2eofLvcf2c+ZSEIqFlVX4351Xt/nDZC5IFAutHi8mKY/eIzjoPhW1u3nJRo4O/qPpICoGpJa97PMU4xLq4yfdZf/toAR2NAoGAJkD7+8/vsWPueoe2SDpm7kH5VtkPqKeTm/wELuCSSxt5k9BEX3WNUZM+hRecAyCwyWi0ipHDi1vpI+EJfAxWL4jUIpS2onWbr6VCinTxJwh05F9vzGDyFgLeXszRQ88xJB9ZIbWtOYP7VO8XvjsoU2flDJmcZyR7VS/kv86UX3s="),
		[3072] = Convert.FromBase64String("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"),
		[4096] = Convert.FromBase64String("MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQCVY1Pst1YZRdxVRORgJGYHjJPyhQdwH/054qmBPIrIdA5q1hyVXUhOUTs9zqUn4AGgGO4sIHwYBqlnYygCNs08gg3/eYN8m3CctLUi0928kZIkIlnEO+deokTTfM+opMdQJKLPfMduhC6mnMfKEidAWwcARzh6UGjkl25LjtX5qt17TbAk+7jXvYoEDY9mEMHG6x1LYG39GCI10DYIgDBNWnUGA68MQkuMjm28EsNpfS1gnJdUfndOLjYuqW0WkNyUMhEsU1JYs9ssTDKtUQ1sB60HiDV4g4ae+4tikphySEeSXPQrNDhr5wDwKQPbWFIna+4jcJQfOXvcOQXjCWSgtec2AnAzQJYMPtYHgmO2EfGXlV/szkuaMuQ80dLl6HxM62XtyIU6fuMdKOFuWt/7ise3YPv8Y9XxdPTQk2Rh27EslkprbWzudS5fyhq0qf0jjdPohgoddj0gGfnnuZ7XZm1OA4cQ+Q4Ak7xWaYfWwAkvVxN25wWzQtBmxU5uJXiSe5LB8JKN5E6abh9JuQfGqk9gXsnDmNVd+BxnNzsDzIEQFi+0F/lv0yEEhkffy7OSRVEVzZEuqDNRhT5qGFKEZIhCrcvSXmcXSjuTuKZM4s6d4OhXe4tmLOMuJWV4JmXdOOW7X8xP4S5DINq3dztUWgnG052dutRZ8h8+Yk7m7QIDAQABAoICAAl6WdLE9wN3eTk3u72V0ZtdAe37HrOwc+J+TP7UFoINSvTgTMP1PScq5DVRrQzQm4nKyyGllfn4Qjs7AUjSrUbPgY/Z58u6GPT4Sh3Bj2ntWnZMb6GRo2ZPqUo5uvsaKUMeb+32HrkWTddoTwy1BiSBIfqUijLIcz89lFPa5hyHCLJQBYLzLZESh3UmXxi8q26xcBReM9xA8bq0URlM+MOPn6kYBr0iX6S1TKUIE7nXpU9h4AAOXgdpyyo+uZsa6cPFQW2sg6b5EkjHNNfmMpHOEt5NeAcDYUEo+HjykBWAHHpex2cOUx4Vc+vIzmPWQLAbmupItD0e6orYW1VCPU4UK89zMV8+npeLZfBVYkYGZZYBP62XuDulUhQMaVfvRDzOxAUbKoyc2fJcTPa9wukE9GBj4xlkMoNGKkBH1Jw4vbsO49h5gOwIQQ1dLe6OU0mVjkF4q6BlpV152JCAVw/Ur1Z4sVc+QvLg+GOzG7Thm6IywCrluPlI0c6BRcSWjSS1askwtPZwRyV/PAuGvOene40NhxJMSkFBQJrBE3f7n8gF1gASOGvswrqEeOZjvsw9cyOc4wNsLS/J5uLjcMLHgFPuG873qHhy75K3hGOLhHE6XXi6jDqGjjRm8idbJS4Zdm0hBOxgU3vBWJsVWLdmQ3UfamD9ilECtseI4PBJAoIBAQDDxndJXCvVZhnkTiYUDS7eADdAm4HzpbOIagkE60hhQPQ7hiavE9FKM5GOtyt4azyRFPOQF4cVKJU8CRBOH9LTa3JTiPVP/qMDcwd4laaTSrF05VymoSwhkjp7d1tf+v+9gT+ft1KAWwFqVzW4g8Y5/t1Vui4jOm3BZzBj2EhzkNFnYSNUTT3vF3qRyu75ixPziGBHTkSZPUxgYJJth4ogWYVdDeHHlKyNva1lX7utIPFS8VxzuVrFRMu4e4vsj9PAB60J12riKl6ZMwKqcvEd6yZafyi4iXavXQyRLZe3KEsXg8W8kabct6m5f+U3E5ZYV3QrfkAy3FFBrNSv1HcfAoIBAQDDV89oX5uNTlnpZob3uHUvCpgu++ZljmvNthXZIfXnBWiCglNHRVeC17x41jfhfg5oEMITatgbFswcgXUHhZJGFvK99ZZLJsf8UPqY+2e3RrUIEnBbN59d6tvRHc0v7HtyTQQq7yXOous3+Ft1VNetSf5fR3N/9Da97UGFB/LxdcaV4yT7sRvrBUSnp8s/B5JOKRtcjdqmp9uwfiO84ZYMtSuQANOnqrH1jjx1C22Xit89CFrnaTt+akbPbbttKtmB9Lyl0V4JYsOQZqn8J5hbm6H1ETI1V5J5al3YR0AIBPmGce5ImQUL3C54cs5vsreLEFBDbYgkJe4HRVRqahxzAoIBAQCmu7VGBjjSsvUkKqZld2DN83MbFBXV8u53JI9v4A4xvccDltoFS6R4RHkYCcn88Z+QlD5nHpKOI5UNn06Cqrm8E4s3t7HtIhmlS2c2fIV0di2yN9DznNpf8RDbrChnEvaRZ61PEisyY89NyN5Yuemt5PCOHVVD7XQiPgbJUh9KRTECkYksN+iiYuWhmypx3s/sHd6ZfAASXlFY14Z9v+yUZomdWcBLYMSgpsUxTBojdaXxlNu/N0ImNdQm1xmxLEEUD7WAZzWBTsJoSThhACl36JguhJOirnglG+MjFahbdfaWHUTft1BcNBNZh6IoiQcHT9wBWrHEXzzY6R/ua83TAoIBABeM1Y9yv1EY2hQebTUeQtpp/5Dig5NIyUxioF2uD3RLnZ7mUV3tSTCYC7vRr6j6xofbRVqL7gPOCsuA+/ftLYZPq/Ik0nq68S9FIAEjhgx9dMPFXVBR81+iOeALJLqbWwKbsF3wuPEhiRQVWAlcMihNHGKmPZF2gscA/H4qSCq+FTPqz4Gch44c83r26rTtl8DeidLtsyeWYxDzFCHoXGupx9ezkdDL7mp5PGar+wljD6jPAg6WDDsgWusVApyVpuVY+QlQpXKiOouFJQcmSuL4b10ZNqFhrmH+5dN2O4z79I013RFZiVc1s1CIHsUumZwlWlfWs6wP+pNb02KE6msCggEASErYbnlBXqPHivX2yAfMmd7PsUyh6AyOah7wDuWC09GAd0I2pU7J3I28ylH02kN5z2NPOgfOpLd0jXtdlMrNTUdBEfktGfOrXrTe+Nule5kIRO/SjYU0Rmbig/XV+w5ujZbwdBHIgr8oBEbkmzubFSGPwk2jTOjwHgJzWSDvSKNDtN4R+ZsmVHolGvp6qmkIPEIeJEexqYnVBxK/j8NYgrY1F8fDmEPPZ7kmRbaMbY+QMxYAFC5suXAypa9u98IPh2MMayXd3rV/LMDNjIoGYbX0DtZjKYn11A8zu/2b4JN0SDYGws1+2LX8uL898fk2ihOSKxJAwNJXklBbhX0+jQ=="),
	};

	// Another key of 2048 bits from rsa_pkcs1_2048_sig_gen_test.json.
	public static readonly byte[] OtherKey2048 = Convert.FromBase64String("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDNpvpcp2v+BJLsV+Cjv/9yctyNHiWtH7M4qgUPAsEE5jEz1rW3xJheu66awDalucAwdNYK7I4luvOSoMQw/wW4jpSIBdPddFEdiIUlCntXQhWtoBXFWQdmhuJTzMlsCBWxKR7nh8wzY7T3fZMOuZjXxYKyTOqc4h3pcieRmJhjon68gKAN5b0vkih3XlpM6wVNWMm+NqBUM2lxoTZC3ZUQ3WlqomjbOqsimdXYj45WJDTRQnCU09+OctHvabTtNNErrDdSI7KiXPIn9zX4FuheFyOTBHaaYIIVTNFYmfwervtpt0ij5e0k04NyWX3j5OKie5UdasfbGC1oCdj/URt/AgMBAAECggEAWj3JYtr8omyzZA5zvqdDmp8YdLwj4EImzNiee6XDuTihopO3Dbqw+fD1f2aVFEfcM+cw/X4sKhZNR6xQKwfdJM08FCwqeeTOq1z6v/RHh1SyWowCwaR9gNnzer5ELKmniyP2Mbb/PhWklW1/GFkM3rIG1eK2mL0ITyYOgu8o/57G28haiV7Io4ZXUPUBuWEl2xu92ZpK5GiK2zBKq9/E4M+5/mtrwNt0yIr4IX7tc4oNBP6NMsHREDcM4cGy9jBlc1BpSUJzCHjm//d62n6aMX34vAWepwgTJTBrjrL6DTo9ifrkdtk0SJK81aQs+Dt7zz4OUbTHjnKzIHpgpwGtsQKBgQDviFuH4lwp0e5DHR9Kznh8T4guktEsSydmyE+JJjEG7wvg3cTeO/BhorpG/+fBMq5n0zfwTcZtrrneVTeR9JifULIkyYGBK1OI0cK11TNJphOTv2YRmVtpiPFDwnjMwmDP6CpqxKZAmAfqsyZkt+4/HEHf5Wfgl/16/oUghxocUwKBgQDbylgiiMgaMNZYHycgUKX+p3PXETAb3W7KxyFOAMD8uUmPHlhQhrFEY8yJoCwud6iSccBYxvafPNE1U5lNinbPYq2eJ1IXcg1i626IjsRQnOpHS1Pze0WPyVbdMd87tux95lnojn5wn+O+ao03Jkw9IOfQiCds52UaQDxo1sR+pQKBgQCdfofIUdKNgMXrhPN1SUq5WcXN8aTtPcD7eMuq/tyPlY+227o88SY93DQkyNBGHJ/GDoAiVdEZfyAhCuEN68iKQBHR1Fh9aNJ1DI685iDh1PvcUqW2/qG3Q153UiABafEj4qA5MXGq2QujiwW8hZ92CYtavsjNSMJXI5C+8XX+lwKBgA7tYC0AQy7cMEKN4xdjwtJXxxtNNIo/8L1e5tkoXfMMFn3c3ryhWTq+2G5kbXu+brl7dkfRQ4CvHbpUci39AHK3TflWzFGBUn1sZfZqU9Txw0uSRyJbNe89CmQ9dd7VXpxyX5rWyqmVgl81V1/ufvEL4hKcnKjd0lUFFdU8+N1tAoGAEB0fSa+wTQZb2MKQAdIS5ze7ppYQhXSjMKnLrMUb9slllPN/upyN4VbCJjcdSZAhkeH2nYShNSGTv/KeMY6zbt5v+6uTtlVez2rdyp4TTCAiCi0ksDptI++MYIpRhnafZv4vayG8OfYnetcGA4uQeHLEcWYJwiN2ITDvA2FkgvI=");

	public static byte[] Pkcs8PrivateKey(int bits = 2048)
	{
		return Keys[bits];
	}

	public static RsaKey ImportKey(int bits = 2048)
	{
		return RsaKey.ImportPkcs8PrivateKey(Keys[bits]);
	}

	// A platform key that holds the key of ImportKey.
	public static RSA CreateBclKey(int bits = 2048)
	{
		RSA key = RSA.Create();
		key.ImportPkcs8PrivateKey(Keys[bits], out _);
		return key;
	}

	// The values of the key of ImportKey, read without the platform.
	public static RSAParameters PrivateParameters(int bits = 2048)
	{
		return ParsePkcs8(Keys[bits]);
	}

	// The values of a PrivateKeyInfo with an RSAPrivateKey of two primes.
	public static RSAParameters ParsePkcs8(byte[] pkcs8)
	{
		AsnReader privateKeyInfo = new AsnReader(pkcs8, AsnEncodingRules.DER).ReadSequence();
		privateKeyInfo.ReadInteger();
		privateKeyInfo.ReadSequence();
		AsnReader key = new AsnReader(privateKeyInfo.ReadOctetString(), AsnEncodingRules.DER).ReadSequence();
		key.ReadInteger();
		return new RSAParameters
		{
			Modulus = Unsigned(key.ReadInteger()),
			Exponent = Unsigned(key.ReadInteger()),
			D = Unsigned(key.ReadInteger()),
			P = Unsigned(key.ReadInteger()),
			Q = Unsigned(key.ReadInteger()),
			DP = Unsigned(key.ReadInteger()),
			DQ = Unsigned(key.ReadInteger()),
			InverseQ = Unsigned(key.ReadInteger())
		};

		static byte[] Unsigned(BigInteger value)
		{
			return value.ToByteArray(isUnsigned: true, isBigEndian: true);
		}
	}

	public static byte[] ExportRsaPublicKey(RsaKey key)
	{
		byte[] rsaPublicKey = new byte[key.RsaPublicKeyLength];
		key.ExportRsaPublicKey(rsaPublicKey);
		return rsaPublicKey;
	}

	public static byte[] ExportRsaPrivateKey(RsaKey key)
	{
		byte[] rsaPrivateKey = new byte[key.RsaPrivateKeyLength];
		key.ExportRsaPrivateKey(rsaPrivateKey);
		return rsaPrivateKey;
	}

	public static int ModulusBits(RSAParameters parameters)
	{
		return (int)Os2Ip(parameters.Modulus).GetBitLength();
	}

	// The examples of pss-vect.txt, the RSASSA-PSS test vectors of PKCS #1 v2.1: keys of 1024 to 1031, 1536 and 2048 bits, and for each, six signatures with SHA-1, MGF1 with SHA-1 and a given salt of 20
	// bytes.
	public static PssExample[] PssExamples => LazyPssExamples.Value;

	private static readonly Lazy<PssExample[]> LazyPssExamples = new(LoadPssExamples);

	public static (HashAlgorithmName Hash, RSASignaturePadding Padding, int HashLength) ParametersOf(SignatureAlgorithm algorithm)
	{
		return algorithm switch
		{
			SignatureAlgorithm.RsaPkcs1Sha256 => (HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1, 32),
			SignatureAlgorithm.RsaPkcs1Sha384 => (HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1, 48),
			SignatureAlgorithm.RsaPkcs1Sha512 => (HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1, 64),
			SignatureAlgorithm.RsaPssSha256 => (HashAlgorithmName.SHA256, RSASignaturePadding.Pss, 32),
			SignatureAlgorithm.RsaPssSha384 => (HashAlgorithmName.SHA384, RSASignaturePadding.Pss, 48),
			SignatureAlgorithm.RsaPssSha512 => (HashAlgorithmName.SHA512, RSASignaturePadding.Pss, 64),
			_ => throw new ArgumentOutOfRangeException(nameof(algorithm))
		};
	}

	public static string HashOid(HashAlgorithmName hash)
	{
		return hash.Name switch
		{
			"SHA256" => "2.16.840.1.101.3.4.2.1",
			"SHA384" => "2.16.840.1.101.3.4.2.2",
			"SHA512" => "2.16.840.1.101.3.4.2.3",
			_ => throw new ArgumentOutOfRangeException(nameof(hash))
		};
	}

	public static BigInteger Os2Ip(ReadOnlySpan<byte> value)
	{
		return new BigInteger(value, isUnsigned: true, isBigEndian: true);
	}

	public static byte[] I2Osp(BigInteger value, int length)
	{
		byte[] bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
		return [.. new byte[length - bytes.Length], .. bytes];
	}

	public static byte[] Integer(BigInteger value)
	{
		AsnWriter writer = new(AsnEncodingRules.DER);
		writer.WriteInteger(value);
		return writer.Encode();
	}

	// RSAPublicKey (RFC 8017, Appendix A.1.1).
	public static byte[] RsaPublicKey(BigInteger modulus, BigInteger exponent)
	{
		return Sequence(Integer(modulus), Integer(exponent));
	}

	// RSAPrivateKey (RFC 8017, Appendix A.1.2) of version 0 with the values of parameters, and any fields after them.
	public static byte[] RsaPrivateKey(RSAParameters parameters, params byte[][] otherFields)
	{
		byte[][] values = [parameters.Modulus!, parameters.Exponent!, parameters.D!, parameters.P!, parameters.Q!, parameters.DP!, parameters.DQ!, parameters.InverseQ!];
		return Sequence([[0x02, 0x01, 0x00], .. values.Select(static value => Integer(Os2Ip(value))), .. otherFields]);
	}

	public static byte[] SubjectPublicKeyInfo(byte[] algorithmIdentifier, byte[] rsaPublicKey)
	{
		return Sequence(algorithmIdentifier, Tlv(0x03, [0x00], rsaPublicKey));
	}

	// A version 1 PrivateKeyInfo (RFC 5958) with no attributes or public key, unless given.
	public static byte[] PrivateKeyInfo(byte[] algorithmIdentifier, byte[] rsaPrivateKey, params byte[][] otherFields)
	{
		return Sequence([[0x02, 0x01, 0x00], algorithmIdentifier, Tlv(0x04, rsaPrivateKey), .. otherFields]);
	}

	// An odd modulus of bits bits that need not be a product of two primes, which only signing needs.
	public static BigInteger Modulus(int bits)
	{
		return BigInteger.One << bits - 1 | new BigInteger(CreateDeterministicSource((bits - 1) / 8), isUnsigned: true, isBigEndian: true) | 1;
	}

	public static byte[] DigestInfo(HashAlgorithmName hash, byte[] digest, bool nullParameters = true)
	{
		byte[] algorithm = nullParameters ? Sequence(Oid(HashOid(hash)), [0x05, 0x00]) : Sequence(Oid(HashOid(hash)));
		return Sequence(algorithm, Tlv(0x04, digest));
	}

	// EM = 0x00 ‖ 0x01 ‖ PS ‖ 0x00 ‖ T (RFC 8017, Sec. 9.2).
	public static byte[] EncodePkcs1(int length, byte[] digestInfo)
	{
		return [0x00, 0x01, .. Enumerable.Repeat((byte)0xFF, length - digestInfo.Length - 3), 0x00, .. digestInfo];
	}

	// EMSA-PSS-ENCODE (RFC 8017, Sec. 9.1.1) with emBits = modBits − 1 and MGF1, written apart from the code under test, with the changes that a case makes: DB before masking, the mask's hash, the bits
	// beyond emBits and the trailer field.
	public static byte[] EncodePss(int modulusBits, HashAlgorithmName hash, byte[] mHash, byte[] salt, byte trailer = 0xBC, Action<byte[]>? changeDb = null, HashAlgorithmName? maskHash = null, byte topBits = 0)
	{
		int emBits = modulusBits - 1;
		int emLength = (emBits + 7) / 8;
		byte[] h = CryptographicOperations.HashData(hash, [.. new byte[8], .. mHash, .. salt]);
		byte[] db = new byte[emLength - h.Length - 1];
		db[db.Length - salt.Length - 1] = 0x01;
		salt.CopyTo(db, db.Length - salt.Length);
		changeDb?.Invoke(db);
		HashAlgorithmName mgfHash = maskHash ?? hash;
		byte[] mask = [];

		for (uint counter = 0; mask.Length < db.Length; ++counter)
		{
			mask = [.. mask, .. CryptographicOperations.HashData(mgfHash, [.. h, (byte)(counter >> 24), (byte)(counter >> 16), (byte)(counter >> 8), (byte)counter])];
		}

		for (int i = 0; i < db.Length; ++i)
		{
			db[i] ^= mask[i];
		}

		db[0] &= (byte)(0xFF >> 8 * emLength - emBits);
		db[0] |= topBits;
		return [.. db, .. h, trailer];
	}

	// Each field of the file is a heading that ends with a colon, then lines of hexadecimal bytes; a key's fields follow "# Private key" after a copy of its public fields, and "# PSS Example" starts a signature, which is skipped.
	private static PssExample[] LoadPssExamples()
	{
		using Stream stream = typeof(RsaTestUtils).Assembly.GetManifestResourceStream("pss-vect.txt") ?? throw new FileNotFoundException("The PKCS #1 test vectors 'pss-vect.txt' are not embedded.");
		using StreamReader reader = new(stream);
		List<PssExample> examples = [];
		Dictionary<string, List<byte>> keyFields = [];
		bool inPrivateKey = false;
		List<byte>? field = null;

		while (reader.ReadLine() is { } line)
		{
			if (line.StartsWith("# Example ", StringComparison.Ordinal) || line.StartsWith("# PSS Example ", StringComparison.Ordinal))
			{
				inPrivateKey = false;
				field = null;

				if (line.StartsWith("# Example ", StringComparison.Ordinal))
				{
					AddExample();
				}
			}
			else if (line is "# Private key" or "# Public key")
			{
				inPrivateKey = line is "# Private key";
				field = null;
			}
			else if (line.StartsWith("# ", StringComparison.Ordinal) && line.EndsWith(':'))
			{
				field = inPrivateKey ? keyFields[line.Substring(2, line.Length - 3)] = [] : null;
			}
			else if (field is not null && line.Length > 0 && line.All(static c => char.IsAsciiHexDigit(c) || c is ' '))
			{
				field.AddRange(Convert.FromHexString(line.Replace(" ", "", StringComparison.Ordinal)));
			}
		}

		AddExample();
		return [.. examples];

		void AddExample()
		{
			if (keyFields.Count is 0)
			{
				return;
			}

			RSAParameters key = new()
			{
				Modulus = [.. keyFields["Modulus"]],
				Exponent = [.. keyFields["Public exponent"]],
				D = [.. keyFields["Exponent"]],
				P = [.. keyFields["Prime 1"]],
				Q = [.. keyFields["Prime 2"]],
				DP = [.. keyFields["Prime exponent 1"]],
				DQ = [.. keyFields["Prime exponent 2"]],
				InverseQ = [.. keyFields["Coefficient"]]
			};
			examples.Add(new PssExample(examples.Count + 1, key));
			keyFields.Clear();
		}
	}

	// RSASP1 (RFC 8017, Sec. 5.2.1) without the Chinese remainder theorem on an encoded message, which need not be valid, as a signature as long as the modulus.
	public static byte[] RawSign(RSAParameters parameters, byte[] encodedMessage)
	{
		BigInteger modulus = Os2Ip(parameters.Modulus);
		return I2Osp(BigInteger.ModPow(Os2Ip(encodedMessage), Os2Ip(parameters.D), modulus), parameters.Modulus!.Length);
	}

	public sealed record PssExample(int Number, RSAParameters Key)
	{
		public override string ToString()
		{
			return $"Example {Number}, {ModulusBits(Key)} bits";
		}
	}
}
