using BenchmarkDotNet.Attributes;
using CryptoBase.EllipticCurves;
using System.Security.Cryptography;

namespace CryptoBase.Benchmark.EllipticCurves;

// The windows of a public key that SM2 encryption and key exchange build once they have taken the key often enough, and those of SM2VerificationCurve that verification builds.
[MemoryDiagnoser]
public class SM2PointTableBenchmark
{
	private AffinePoint<SM2Field52> _point;

	[GlobalSetup]
	public void Setup()
	{
		FieldElement<SM2Order>.ImportReduced(RandomNumberGenerator.GetBytes(SM2Order.ByteLength), out FieldElement<SM2Order> privateKey);
		ECGroup<SM2Curve, SM2Field52, SM2Order>.MultiplyBaseToAffine(in privateKey, out _point);
	}

	[Benchmark]
	public object Build()
	{
		return new ECPointTable<SM2Curve, SM2Field52, SM2Order>(in _point);
	}

	[Benchmark]
	public object BuildVerification()
	{
		return new ECPointTable<SM2VerificationCurve, SM2Field52, SM2Order>(in _point);
	}
}
