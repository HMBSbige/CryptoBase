using CryptoBase.Abstractions.Hashes;
using CryptoBase.Hashes.Sha1;
using CryptoBase.Hashes.Sha2;
using CryptoBase.Otp;
using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Tests.Otp;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class TotpTest
{
	// RFC 6238 Appendix B with the per-hash seeds of verified erratum 2866, which match the reference code of Appendix A.
	private static readonly byte[] Sha1Seed = "12345678901234567890"u8.ToArray();
	private static readonly byte[] Sha256Seed = "12345678901234567890123456789012"u8.ToArray();
	private static readonly byte[] Sha512Seed = "1234567890123456789012345678901234567890123456789012345678901234"u8.ToArray();

	private static readonly TotpParameters Rfc6238Vectors = new(OtpCodeFormat.Decimal(8));

	private static readonly byte[] SteamSecret = Convert.FromBase64String("zvIayp3JPvtvX/QGHqsqKBk/44s=");

	[Test]
	[Arguments(59L, "94287082")]
	[Arguments(1111111109L, "07081804")]
	[Arguments(1111111111L, "14050471")]
	[Arguments(1234567890L, "89005924")]
	[Arguments(2000000000L, "69279037")]
	[Arguments(20000000000L, "65353130")]
	public Task Rfc6238Sha1Vector(long unixTime, string expected)
	{
		return VerifyVector<Sha1Core>(Sha1Seed, unixTime, expected);
	}

	[Test]
	[Arguments(59L, "46119246")]
	[Arguments(1111111109L, "68084774")]
	[Arguments(1111111111L, "67062674")]
	[Arguments(1234567890L, "91819424")]
	[Arguments(2000000000L, "90698825")]
	[Arguments(20000000000L, "77737706")]
	public Task Rfc6238Sha256Vector(long unixTime, string expected)
	{
		return VerifyVector<Sha256Core>(Sha256Seed, unixTime, expected);
	}

	[Test]
	[Arguments(59L, "90693936")]
	[Arguments(1111111109L, "25091201")]
	[Arguments(1111111111L, "99943326")]
	[Arguments(1234567890L, "93441116")]
	[Arguments(2000000000L, "38618901")]
	[Arguments(20000000000L, "47863826")]
	public Task Rfc6238Sha512Vector(long unixTime, string expected)
	{
		return VerifyVector<Sha512Core>(Sha512Seed, unixTime, expected);
	}

	private static async Task VerifyVector<TCore>(byte[] seed, long unixTime, string expected) where TCore : unmanaged, IHmacHashCore<TCore>
	{
		DateTimeOffset time = DateTimeOffset.FromUnixTimeSeconds(unixTime);
		using Totp<TCore> totp = Totp<TCore>.Create(seed, Rfc6238Vectors);

		await Assert.That(Generate(totp, time)).IsEqualTo(expected);
		await Assert.That(totp.Verify(time, expected, 0, 0, out long timeStep)).IsTrue();
		await Assert.That(timeStep).IsEqualTo(unixTime / 30);
	}

	// The T column of RFC 6238 Appendix B and the examples of section 4.2.
	[Test]
	[Arguments(0L, 0L)]
	[Arguments(29L, 0L)]
	[Arguments(59L, 1L)]
	[Arguments(60L, 2L)]
	[Arguments(1111111109L, 0x23523ECL)]
	[Arguments(1234567890L, 0x273EF07L)]
	[Arguments(20000000000L, 0x27BC86AAL)]
	public async Task TimeStepIsTheFloorOfElapsedSteps(long unixTime, long expected)
	{
		await Assert.That(TotpParameters.Rfc6238.GetTimeStep(DateTimeOffset.FromUnixTimeSeconds(unixTime))).IsEqualTo(expected);
	}

	[Test]
	public async Task FractionsOfASecondAreDiscarded()
	{
		DateTimeOffset time = DateTimeOffset.FromUnixTimeSeconds(59).AddTicks(TimeSpan.TicksPerSecond - 1);

		await Assert.That(TotpParameters.Rfc6238.GetTimeStep(time)).IsEqualTo(1L);

		// Before the Unix epoch the time is still rounded down: 0.1 seconds before it is 1 second after T0.
		TotpParameters beforeEpoch = new(OtpCodeFormat.Decimal(6), 1, -2);
		await Assert.That(beforeEpoch.GetTimeStep(DateTimeOffset.UnixEpoch.AddTicks(-TimeSpan.TicksPerSecond / 10))).IsEqualTo(1L);
	}

	// The custom parameters reduce to HOTP with T as the counter; HOTP is checked against RFC 4226.
	[Test]
	[Arguments(1000L, 60, 1000L, 0UL)]
	[Arguments(1000L, 60, 1059L, 0UL)]
	[Arguments(1000L, 60, 1060L, 1UL)]
	[Arguments(-3600L, 1, 0L, 3600UL)]
	[Arguments(0L, int.MaxValue, 20000000000L, 9UL)]
	public async Task CustomParametersMatchHotp(long initialUnixTime, int timeStepSeconds, long unixTime, ulong expectedStep)
	{
		TotpParameters parameters = new(OtpCodeFormat.Decimal(7), timeStepSeconds, initialUnixTime);
		DateTimeOffset time = DateTimeOffset.FromUnixTimeSeconds(unixTime);
		using Totp<Sha256Core> totp = Totp<Sha256Core>.Create(Sha256Seed, parameters);
		using Hotp<Sha256Core> hotp = Hotp<Sha256Core>.Create(Sha256Seed, OtpCodeFormat.Decimal(7));
		char[] expected = new char[7];
		hotp.Generate(expectedStep, expected);

		await Assert.That(parameters.GetTimeStep(time)).IsEqualTo((long)expectedStep);
		await Assert.That(Generate(totp, time)).IsEqualTo(new string(expected));
	}

	[Test]
	public async Task LatestTimeMatchesHotp()
	{
		DateTimeOffset time = DateTimeOffset.MaxValue;
		long step = TotpParameters.Rfc6238.GetTimeStep(time);
		using Totp<Sha1Core> totp = Totp<Sha1Core>.Create(Sha1Seed, TotpParameters.Rfc6238);
		using Hotp<Sha1Core> hotp = Hotp<Sha1Core>.Create(Sha1Seed, OtpCodeFormat.Decimal(6));
		char[] expected = new char[6];
		hotp.Generate((ulong)step, expected);

		await Assert.That(step).IsEqualTo(253402300799L / 30);
		await Assert.That(Generate(totp, time)).IsEqualTo(new string(expected));
		await Assert.That(totp.Verify(time, new string(expected), 1, 1, out long matched)).IsTrue();
		await Assert.That(matched).IsEqualTo(step);
	}

	[Test]
	public async Task WindowAcceptsStepsBeforeAndAfter()
	{
		using Totp<Sha1Core> totp = Totp<Sha1Core>.Create(Sha1Seed, Rfc6238Vectors);

		// 94287082 is the code of step 1, from 30 to 59 seconds.
		DateTimeOffset stepBefore = DateTimeOffset.FromUnixTimeSeconds(60);
		DateTimeOffset stepAfter = DateTimeOffset.FromUnixTimeSeconds(29);

		await Assert.That(totp.Verify(stepBefore, "94287082", 1, 0, out long timeStep)).IsTrue();
		await Assert.That(timeStep).IsEqualTo(1L);
		await Assert.That(totp.Verify(stepBefore, "94287082", 0, 5, out timeStep)).IsFalse();
		await Assert.That(timeStep).IsEqualTo(0L);

		await Assert.That(totp.Verify(stepAfter, "94287082", 0, 1, out timeStep)).IsTrue();
		await Assert.That(timeStep).IsEqualTo(1L);
		await Assert.That(totp.Verify(stepAfter, "94287082", 5, 0, out _)).IsFalse();

		DateTimeOffset twoStepsLater = DateTimeOffset.FromUnixTimeSeconds(119);
		await Assert.That(totp.Verify(twoStepsLater, "94287082", 1, 1, out _)).IsFalse();
		await Assert.That(totp.Verify(twoStepsLater, "94287082", 2, 0, out timeStep)).IsTrue();
		await Assert.That(timeStep).IsEqualTo(1L);
	}

	[Test]
	public async Task WindowLeavesOutStepsBeforeZero()
	{
		using Totp<Sha1Core> totp = Totp<Sha1Core>.Create(Sha1Seed, Rfc6238Vectors);
		DateTimeOffset initialTime = DateTimeOffset.FromUnixTimeSeconds(0);

		await Assert.That(totp.Verify(initialTime, "94287082", int.MaxValue, 1, out long timeStep)).IsTrue();
		await Assert.That(timeStep).IsEqualTo(1L);
	}

	[Test]
	public async Task TimesBeforeT0AreRejected()
	{
		TotpParameters parameters = new(OtpCodeFormat.Decimal(6), 30, 1000);
		DateTimeOffset early = DateTimeOffset.FromUnixTimeSeconds(999);
		using Totp<Sha1Core> totp = Totp<Sha1Core>.Create(Sha1Seed, parameters);

		await Assert.That(() => parameters.GetTimeStep(early)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("time");
		await Assert.That(() => totp.Generate(early, new char[6])).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("time");
		await Assert.That(() => totp.Verify(early, "000000", 1, 1, out _)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("time");
		await Assert.That(parameters.GetTimeStep(DateTimeOffset.FromUnixTimeSeconds(1000))).IsEqualTo(0L);
	}

	[Test]
	public async Task RejectsInvalidParameters()
	{
		OtpCodeFormat format = OtpCodeFormat.Decimal(6);
		long minUnixTime = DateTimeOffset.MinValue.ToUnixTimeSeconds();
		long maxUnixTime = DateTimeOffset.MaxValue.ToUnixTimeSeconds();

		await Assert.That(() => new TotpParameters(default)).ThrowsExactly<ArgumentException>().WithParameterName("format");
		await Assert.That(() => new TotpParameters(format, 0)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("timeStepSeconds");
		await Assert.That(() => new TotpParameters(format, -30)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("timeStepSeconds");
		await Assert.That(() => new TotpParameters(format, 30, minUnixTime - 1)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("initialUnixTime");
		await Assert.That(() => new TotpParameters(format, 30, maxUnixTime + 1)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("initialUnixTime");
		await Assert.That(new TotpParameters(format, 1, minUnixTime).InitialUnixTime).IsEqualTo(minUnixTime);
		await Assert.That(new TotpParameters(format, int.MaxValue, maxUnixTime).TimeStepSeconds).IsEqualTo(int.MaxValue);

		await Assert.That(() => default(TotpParameters).GetTimeStep(DateTimeOffset.UnixEpoch)).ThrowsExactly<ArgumentException>();
		await Assert.That(() => Totp<Sha1Core>.Create(Sha1Seed, default)).ThrowsExactly<ArgumentException>().WithParameterName("parameters");
		await Assert.That(() => Totp<Sha1Core>.Create([], TotpParameters.Rfc6238)).ThrowsExactly<ArgumentException>().WithParameterName("key");
	}

	[Test]
	public async Task RejectsInvalidArguments()
	{
		using Totp<Sha1Core> totp = Totp<Sha1Core>.Create(Sha1Seed, TotpParameters.Rfc6238);
		DateTimeOffset time = DateTimeOffset.FromUnixTimeSeconds(59);
		char[] destination = "#####".ToCharArray();

		await Assert.That(() => totp.Generate(time, destination)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
		await Assert.That(new string(destination)).IsEqualTo("#####");
		await Assert.That(() => totp.Verify(time, "287082", -1, 0, out _)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("stepsBefore");
		await Assert.That(() => totp.Verify(time, "287082", 0, -1, out _)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("stepsAfter");
		await Assert.That(totp.Verify(time, "28708", 1, 1, out _)).IsFalse();
	}

	[Test]
	public async Task DisposedInstanceThrows()
	{
		Totp<Sha1Core> totp = Totp<Sha1Core>.Create(Sha1Seed, TotpParameters.Rfc6238);
		totp.Dispose();
		totp.Dispose();

		await Assert.That(() => totp.Generate(DateTimeOffset.UnixEpoch, new char[6])).ThrowsExactly<ObjectDisposedException>();
		await Assert.That(() => totp.Verify(DateTimeOffset.UnixEpoch, "000000", 0, 0, out _)).ThrowsExactly<ObjectDisposedException>();
	}

	[Test]
	public async Task PresetsHaveTheirParameters()
	{
		await Assert.That(TotpParameters.Rfc6238).IsEqualTo(new TotpParameters(OtpCodeFormat.Decimal(6)));
		await Assert.That(TotpParameters.SteamGuard).IsEqualTo(new TotpParameters(OtpCodeFormat.SteamGuard));
		await Assert.That(OtpCodeFormat.SteamGuard.Length).IsEqualTo(5);
		await Assert.That(OtpCodeFormat.SteamGuard).IsNotEqualTo(OtpCodeFormat.Decimal(6));
	}

	[Test]
	[Arguments(1616374841L, "2F9J5")]
	[Arguments(1616374859L, "2F9J5")]
	[Arguments(1616374860L, "3HJXN")]
	[Arguments(0L, "8J8QF")]
	[Arguments(20000000000L, "H9HP2")]
	public Task SteamGuardVector(long unixTime, string expected)
	{
		return VerifySteamGuard(SteamSecret, unixTime, expected);
	}

	[Test]
	[Arguments(59L, "PV9M4")]
	[Arguments(1111111109L, "PY4YB")]
	[Arguments(1234567890L, "VHHQY")]
	[Arguments(2000000000L, "9N776")]
	[Arguments(20000000000L, "R5DMB")]
	public Task SteamGuardRfcSeedVector(long unixTime, string expected)
	{
		return VerifySteamGuard(Sha1Seed, unixTime, expected);
	}

	private static async Task VerifySteamGuard(byte[] secret, long unixTime, string expected)
	{
		DateTimeOffset time = DateTimeOffset.FromUnixTimeSeconds(unixTime);
		using Totp<Sha1Core> totp = Totp<Sha1Core>.Create(secret, TotpParameters.SteamGuard);

		await Assert.That(Generate(totp, time)).IsEqualTo(expected);
		await Assert.That(totp.Verify(time.AddSeconds(30), expected, 1, 0, out long timeStep)).IsTrue();
		await Assert.That(timeStep).IsEqualTo(unixTime / 30);
		await Assert.That(totp.Verify(time, expected.ToLowerInvariant(), 0, 0, out _)).IsFalse();
	}

	private static string Generate<TCore>(Totp<TCore> totp, DateTimeOffset time) where TCore : unmanaged, IHmacHashCore<TCore>
	{
		Span<char> code = stackalloc char[totp.Parameters.Format.Length];
		int written = totp.Generate(time, code);
		return new string(code.Slice(0, written));
	}
}
