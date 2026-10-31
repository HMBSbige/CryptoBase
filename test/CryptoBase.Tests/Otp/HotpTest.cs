using CryptoBase.Hashes.MD5;
using CryptoBase.Hashes.Sha1;
using CryptoBase.Otp;
using System.Diagnostics.CodeAnalysis;

namespace CryptoBase.Tests.Otp;

[SuppressMessage("ReSharper", "AccessToDisposedClosure")]
public class HotpTest
{
	// RFC 4226 Appendix D.
	private static readonly byte[] Rfc4226Secret = "12345678901234567890"u8.ToArray();

	[Test]
	[Arguments(0UL, "755224")]
	[Arguments(1UL, "287082")]
	[Arguments(2UL, "359152")]
	[Arguments(3UL, "969429")]
	[Arguments(4UL, "338314")]
	[Arguments(5UL, "254676")]
	[Arguments(6UL, "287922")]
	[Arguments(7UL, "162583")]
	[Arguments(8UL, "399871")]
	[Arguments(9UL, "520489")]
	public async Task Rfc4226Vector(ulong counter, string expected)
	{
		using Hotp<Sha1Core> hotp = Hotp<Sha1Core>.Create(Rfc4226Secret, OtpCodeFormat.Decimal(6));

		await Assert.That(Generate(hotp, counter)).IsEqualTo(expected);
		await Assert.That(hotp.Verify(counter, expected, 0, out ulong matched)).IsTrue();
		await Assert.That(matched).IsEqualTo(counter);
	}

	// The truncated values of RFC 4226 Appendix D modulo 10^9; counters 1 and 7 need zero padding.
	[Test]
	[Arguments(0UL, "284755224")]
	[Arguments(1UL, "094287082")]
	[Arguments(2UL, "137359152")]
	[Arguments(7UL, "082162583")]
	public async Task NineDigitsReduceTheTruncatedValue(ulong counter, string expected)
	{
		using Hotp<Sha1Core> hotp = Hotp<Sha1Core>.Create(Rfc4226Secret, OtpCodeFormat.Decimal(9));

		await Assert.That(Generate(hotp, counter)).IsEqualTo(expected);
	}

	[Test]
	public async Task GenerateWritesOnlyTheCode()
	{
		using Hotp<Sha1Core> hotp = Hotp<Sha1Core>.Create(Rfc4226Secret, OtpCodeFormat.Decimal(6));
		char[] destination = "##########".ToCharArray();

		int written = hotp.Generate(0, destination);

		await Assert.That(written).IsEqualTo(6);
		await Assert.That(new string(destination)).IsEqualTo("755224####");
	}

	[Test]
	public async Task LookAheadAcceptsLaterCounters()
	{
		using Hotp<Sha1Core> hotp = Hotp<Sha1Core>.Create(Rfc4226Secret, OtpCodeFormat.Decimal(6));

		// Counter 8.
		await Assert.That(hotp.Verify(5, "399871", 3, out ulong matched)).IsTrue();
		await Assert.That(matched).IsEqualTo(8UL);

		await Assert.That(hotp.Verify(5, "399871", 2, out matched)).IsFalse();
		await Assert.That(matched).IsEqualTo(0UL);

		// Counters before the expected one are never accepted.
		await Assert.That(hotp.Verify(9, "399871", 100, out _)).IsFalse();
	}

	// Counters 336 and 2205 share 143951 under the RFC 4226 secret.
	[Test]
	public async Task VerifyReturnsTheFirstMatch()
	{
		using Hotp<Sha1Core> hotp = Hotp<Sha1Core>.Create(Rfc4226Secret, OtpCodeFormat.Decimal(6));

		await Assert.That(Generate(hotp, 336)).IsEqualTo("143951");
		await Assert.That(Generate(hotp, 2205)).IsEqualTo("143951");

		await Assert.That(hotp.Verify(0, "143951", 2205, out ulong matched)).IsTrue();
		await Assert.That(matched).IsEqualTo(336UL);

		await Assert.That(hotp.Verify(337, "143951", 1868, out matched)).IsTrue();
		await Assert.That(matched).IsEqualTo(2205UL);
	}

	[Test]
	public async Task WindowStopsAtTheLastCounterWithoutWrapping()
	{
		using Hotp<Sha1Core> hotp = Hotp<Sha1Core>.Create(Rfc4226Secret, OtpCodeFormat.Decimal(6));

		await Assert.That(Generate(hotp, ulong.MaxValue - 1)).IsEqualTo("488204");
		await Assert.That(Generate(hotp, ulong.MaxValue)).IsEqualTo("094451");

		await Assert.That(hotp.Verify(ulong.MaxValue - 1, "094451", int.MaxValue, out ulong matched)).IsTrue();
		await Assert.That(matched).IsEqualTo(ulong.MaxValue);

		// Counter 0 would follow ulong.MaxValue if the window wrapped.
		await Assert.That(hotp.Verify(ulong.MaxValue - 1, "755224", 5, out _)).IsFalse();
	}

	[Test]
	[Arguments("")]
	[Arguments("75522")]
	[Arguments("7552240")]
	[Arguments("755225")]
	[Arguments("75522\0")]
	public async Task VerifyRejectsOtherCodes(string code)
	{
		using Hotp<Sha1Core> hotp = Hotp<Sha1Core>.Create(Rfc4226Secret, OtpCodeFormat.Decimal(6));

		await Assert.That(hotp.Verify(0, code, 0, out ulong matched)).IsFalse();
		await Assert.That(matched).IsEqualTo(0UL);
	}

	[Test]
	public async Task KeyIsCopied()
	{
		byte[] key = Rfc4226Secret.ToArray();
		using Hotp<Sha1Core> hotp = Hotp<Sha1Core>.Create(key, OtpCodeFormat.Decimal(6));
		key.AsSpan().Clear();

		await Assert.That(Generate(hotp, 0)).IsEqualTo("755224");
	}

	[Test]
	public async Task RejectsInvalidArguments()
	{
		await Assert.That(() => Hotp<Sha1Core>.Create([], OtpCodeFormat.Decimal(6))).ThrowsExactly<ArgumentException>().WithParameterName("key");
		await Assert.That(() => Hotp<Sha1Core>.Create(Rfc4226Secret, default)).ThrowsExactly<ArgumentException>().WithParameterName("format");

		using Hotp<Sha1Core> hotp = Hotp<Sha1Core>.Create(Rfc4226Secret, OtpCodeFormat.Decimal(6));
		char[] destination = "#####".ToCharArray();

		await Assert.That(() => hotp.Generate(0, destination)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
		await Assert.That(new string(destination)).IsEqualTo("#####");
		await Assert.That(() => hotp.Verify(0, "755224", -1, out _)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("lookAhead");
	}

	// Dynamic truncation reads up to byte 18, past the 16 bytes of MD5.
	[Test]
	public async Task RejectsHashesShorterThan20Bytes()
	{
		await Assert.That(() => Hotp<MD5Core>.Create(Rfc4226Secret, OtpCodeFormat.Decimal(6))).ThrowsExactly<NotSupportedException>();
		await Assert.That(() => Totp<MD5Core>.Create(Rfc4226Secret, TotpParameters.Rfc6238)).ThrowsExactly<NotSupportedException>();
	}

	[Test]
	public async Task DisposedInstanceThrows()
	{
		Hotp<Sha1Core> hotp = Hotp<Sha1Core>.Create(Rfc4226Secret, OtpCodeFormat.Decimal(6));
		hotp.Dispose();
		hotp.Dispose();

		await Assert.That(() => hotp.Generate(0, new char[6])).ThrowsExactly<ObjectDisposedException>();
		await Assert.That(() => hotp.Verify(0, "755224", 0, out _)).ThrowsExactly<ObjectDisposedException>();
	}

	[Test]
	[Arguments(6)]
	[Arguments(9)]
	public async Task DecimalAcceptsSixToNineDigits(int digits)
	{
		await Assert.That(OtpCodeFormat.Decimal(digits).Length).IsEqualTo(digits);
	}

	[Test]
	[Arguments(int.MinValue)]
	[Arguments(0)]
	[Arguments(5)]
	[Arguments(10)]
	public async Task DecimalRejectsOtherDigitCounts(int digits)
	{
		await Assert.That(() => OtpCodeFormat.Decimal(digits)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("digits");
	}

	private static string Generate(Hotp<Sha1Core> hotp, ulong counter)
	{
		Span<char> code = stackalloc char[hotp.Format.Length];
		int written = hotp.Generate(counter, code);
		return new string(code.Slice(0, written));
	}
}
