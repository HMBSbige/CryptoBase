using CryptoBase.Kdf;
using CryptoBase.Kdf.Argon2;
using System.Text;
using static CryptoBase.Tests.TestUtils;

namespace CryptoBase.Tests.Kdf.Argon2;

public class Argon2PasswordHasherTest
{
	// A hashtest vector of test.c, cited below.
	private const string SmallReferenceString = "$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E";

	// The version 0x13 hashtest vectors of https://github.com/P-H-C/phc-winner-argon2/blob/f57e61e19229e23c4445b85494dbf7c07de721cb/src/test.c, except those using 256 MiB or more, and the example of https://github.com/P-H-C/phc-winner-argon2/blob/f57e61e19229e23c4445b85494dbf7c07de721cb/README.md, with four lanes and a 24-byte hash.
	[Test]
	[Argon2LargeMemory]
	[Arguments("password", "somesalt", Argon2Type.Argon2i, 65536, 2, 1, "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("password", "somesalt", Argon2Type.Argon2i, 256, 2, 1, "$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$iekCn0Y3spW+sCcFanM2xBT63UP2sghkUoHLIUpWRS8")]
	[Arguments("password", "somesalt", Argon2Type.Argon2i, 256, 2, 2, "$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E")]
	[Arguments("password", "somesalt", Argon2Type.Argon2i, 65536, 1, 1, "$argon2i$v=19$m=65536,t=1,p=1$c29tZXNhbHQ$0WgHXE2YXhPr6uVgz4uUw7XYoWxRkWtvSsLaOsEbvs8")]
	[Arguments("password", "somesalt", Argon2Type.Argon2i, 65536, 4, 1, "$argon2i$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$qqlT1YrzcGzj3xrv1KZKhOMdf1QXUjHxKFJZ+IF0zls")]
	[Arguments("differentpassword", "somesalt", Argon2Type.Argon2i, 65536, 2, 1, "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$FK6NoBr+qHAMI1jc73xTWNkCEoK9iGY6RWL1n7dNIu4")]
	[Arguments("password", "diffsalt", Argon2Type.Argon2i, 65536, 2, 1, "$argon2i$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ$sDV8zPvvkfOGCw26RHsjSMvv7K2vmQq/6cxAcmxSEnE")]
	[Arguments("password", "somesalt", Argon2Type.Argon2i, 65536, 2, 4, "$argon2i$v=19$m=65536,t=2,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG")]
	[Arguments("password", "somesalt", Argon2Type.Argon2id, 65536, 2, 1, "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc")]
	[Arguments("password", "somesalt", Argon2Type.Argon2id, 256, 2, 1, "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4")]
	[Arguments("password", "somesalt", Argon2Type.Argon2id, 256, 2, 2, "$argon2id$v=19$m=256,t=2,p=2$c29tZXNhbHQ$bQk8UB/VmZZF4Oo79iDXuL5/0ttZwg2f/5U52iv1cDc")]
	[Arguments("password", "somesalt", Argon2Type.Argon2id, 65536, 1, 1, "$argon2id$v=19$m=65536,t=1,p=1$c29tZXNhbHQ$9qWtwbpyPd3vm1rB1GThgPzZ3/ydHL92zKL+15XZypg")]
	[Arguments("password", "somesalt", Argon2Type.Argon2id, 65536, 4, 1, "$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$kCXUjmjvc5XMqQedpMTsOv+zyJEf5PhtGiUghW9jFyw")]
	[Arguments("differentpassword", "somesalt", Argon2Type.Argon2id, 65536, 2, 1, "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$C4TWUs9rDEvq7w3+J4umqA32aWKB1+DSiRuBfYxFj94")]
	[Arguments("password", "diffsalt", Argon2Type.Argon2id, 65536, 2, 1, "$argon2id$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ$vfMrBczELrFdWP0ZsfhWsRPaHppYdP3MVEMIVlqoFBw")]
	public async Task MatchesReferenceImplementationString(string password, string salt, Argon2Type type, int memorySizeInKibibytes, int iterations, int parallelism, string encoded)
	{
		Argon2Parameters parameters = new(memorySizeInKibibytes, iterations, parallelism);
		int hashLength = FromBase64(encoded.Substring(encoded.LastIndexOf('$') + 1)).Length;

		using (Assert.Multiple())
		{
			await Assert.That(Argon2PasswordHasher.Verify(Encoding.UTF8.GetBytes(password), encoded)).IsTrue();
			await Assert.That(Argon2PasswordHasher.Hash(Encoding.UTF8.GetBytes(password), Encoding.UTF8.GetBytes(salt), parameters, type, hashLength)).IsEqualTo(encoded);
			await Assert.That(Argon2PasswordHasher.NeedsRehash(encoded, parameters, type, hashLength)).IsFalse();
		}
	}

	// The hash of "passwore" from test.c above.
	[Test]
	[Argon2LargeMemory]
	public async Task RejectsTheReferenceImplementationMismatch()
	{
		const string encoded = "$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$8iIuixkI73Js3G1uMbezQXD0b8LG4SXGsOwoQkdAQIM";

		using (Assert.Multiple())
		{
			await Assert.That(Argon2PasswordHasher.Verify("password"u8, encoded)).IsFalse();
			await Assert.That(Argon2PasswordHasher.Verify("passwore"u8, encoded)).IsTrue();
		}
	}

	// The example of https://github.com/C2SP/C2SP/blob/fc7f312aff098ed080f3dd5a3da4fd820be17a2e/phc-strings.md, which uses the secret "pepper".
	[Test]
	[Argon2LargeMemory]
	public async Task VerificationUsesTheSecret()
	{
		const string encoded = "$argon2id$v=19$m=65536,t=2,p=1$gZiV/M1gPc22ElAH/Jh1Hw$CWOrkoo7oJBQ/iyh7uJ0LO2aLEfrHwTWllSAxT0zRno";

		using (Assert.Multiple())
		{
			await Assert.That(Argon2PasswordHasher.Verify("hunter2"u8, encoded, "pepper"u8)).IsTrue();
			await Assert.That(Argon2PasswordHasher.Verify("hunter2"u8, encoded)).IsFalse();
			await Assert.That(Argon2PasswordHasher.Verify("hunter2"u8, encoded, "peppers"u8)).IsFalse();
			await Assert.That(Argon2PasswordHasher.Verify("hunter3"u8, encoded, "pepper"u8)).IsFalse();
		}
	}

	[Test]
	public async Task ChangingAnyBitOfTheSaltOrHashFailsVerification()
	{
		string[] fields = SmallReferenceString.Split('$');
		byte[] salt = FromBase64(fields[4]);
		byte[] hash = FromBase64(fields[5]);
		List<string> changed = [];

		for (int bit = 0; bit < salt.Length * 8; ++bit)
		{
			byte[] changedSalt = (byte[])salt.Clone();
			changedSalt[bit / 8] ^= (byte)(1 << bit % 8);
			changed.Add($"${fields[1]}${fields[2]}${fields[3]}${ToBase64(changedSalt)}${fields[5]}");
		}

		for (int bit = 0; bit < hash.Length * 8; ++bit)
		{
			byte[] changedHash = (byte[])hash.Clone();
			changedHash[bit / 8] ^= (byte)(1 << bit % 8);
			changed.Add($"${fields[1]}${fields[2]}${fields[3]}${fields[4]}${ToBase64(changedHash)}");
		}

		await Assert.That(changed.Where(static encoded => Argon2PasswordHasher.Verify("password"u8, encoded))).IsEmpty();
	}

	[Test]
	[Arguments("$argon2d$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E")]
	[Arguments("$argon2id$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E")]
	[Arguments("$argon2i$v=19$m=255,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E")]
	[Arguments("$argon2i$v=19$m=264,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E")]
	[Arguments("$argon2i$v=19$m=256,t=1,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E")]
	[Arguments("$argon2i$v=19$m=256,t=3,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E")]
	[Arguments("$argon2i$v=19$m=256,t=2,p=1$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E")]
	[Arguments("$argon2i$v=19$m=256,t=2,p=3$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2E")]
	[Arguments("$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1O")]
	[Arguments("$argon2i$v=19$m=256,t=2,p=2$c29tZXNhbHQ$T/XOJ2mh1/TIpJHfCdQan76Q5esCFVoT5MAeIM1Oq2EA")]
	public async Task ChangingTheSettingsFailsVerification(string encoded)
	{
		await Assert.That(Argon2PasswordHasher.Verify("password"u8, encoded)).IsFalse();
	}

	[Test]
	[Arguments(Argon2Type.Argon2d)]
	[Arguments(Argon2Type.Argon2i)]
	[Arguments(Argon2Type.Argon2id)]
	public async Task HashRoundTrips(Argon2Type type)
	{
		Argon2Parameters parameters = new(64, 2, 2);
		byte[] password = CreateDeterministicSource(20);
		byte[] secret = CreateDeterministicSource(8);
		string encoded = Argon2PasswordHasher.Hash(password, parameters, type);
		string peppered = Argon2PasswordHasher.Hash(password, parameters, type, secret: secret);
		string[] fields = encoded.Split('$');

		using (Assert.Multiple())
		{
			await Assert.That(fields[1]).IsEqualTo(type.ToString().ToLowerInvariant());
			await Assert.That(fields[2]).IsEqualTo("v=19");
			await Assert.That(fields[3]).IsEqualTo("m=64,t=2,p=2");
			await Assert.That(FromBase64(fields[4]).Length).IsEqualTo(16);
			await Assert.That(FromBase64(fields[5]).Length).IsEqualTo(32);
			await Assert.That(Argon2PasswordHasher.Verify(password, encoded)).IsTrue();
			await Assert.That(Argon2PasswordHasher.Verify(password.AsSpan(1), encoded)).IsFalse();
			await Assert.That(Argon2PasswordHasher.Verify(password, encoded, secret)).IsFalse();
			await Assert.That(Argon2PasswordHasher.Verify(password, peppered, secret)).IsTrue();
			await Assert.That(Argon2PasswordHasher.Verify(password, peppered)).IsFalse();
			await Assert.That(Argon2PasswordHasher.Hash(password, parameters, type)).IsNotEqualTo(encoded);
		}
	}

	[Test]
	[MatrixDataSource]
	public async Task HashEncodesTheSaltAndTheDerivedKey([Matrix(Argon2Type.Argon2d, Argon2Type.Argon2i, Argon2Type.Argon2id)] Argon2Type type, [Matrix(8, 9, 10, 300)] int saltLength, [Matrix(4, 5, 6, 64, 300)] int hashLength)
	{
		Argon2Parameters parameters = new(16, 1, 1);
		byte[] password = CreateDeterministicSource(9);
		byte[] salt = CreateDeterministicSource(saltLength);
		byte[] secret = CreateDeterministicSource(3);
		byte[] hash = new byte[hashLength];
		Argon2Core.DeriveKey(password, salt, secret, default, type, parameters, -1, hash);
		string expected = $"${type.ToString().ToLowerInvariant()}$v=19$m=16,t=1,p=1${ToBase64(salt)}${ToBase64(hash)}";

		using (Assert.Multiple())
		{
			await Assert.That(Argon2PasswordHasher.Hash(password, salt, parameters, type, hashLength, secret)).IsEqualTo(expected);
			await Assert.That(Argon2PasswordHasher.Verify(password, expected, secret)).IsTrue();
		}
	}

	[Test]
	public async Task RandomSaltHasTheRequestedLength()
	{
		string encoded = Argon2PasswordHasher.Hash("password"u8, new Argon2Parameters(8, 1, 1), Argon2Type.Argon2id, saltLength: 300, hashLength: 4);
		string[] fields = encoded.Split('$');

		using (Assert.Multiple())
		{
			await Assert.That(FromBase64(fields[4]).Length).IsEqualTo(300);
			await Assert.That(FromBase64(fields[5]).Length).IsEqualTo(4);
			await Assert.That(Argon2PasswordHasher.Verify("password"u8, encoded)).IsTrue();
		}
	}

	[Test]
	public async Task NeedsRehashComparesTheSettings()
	{
		Argon2Parameters parameters = new(64, 2, 2);
		string encoded = Argon2PasswordHasher.Hash("password"u8, parameters, Argon2Type.Argon2id, hashLength: 24);

		using (Assert.Multiple())
		{
			await Assert.That(Argon2PasswordHasher.NeedsRehash(encoded, parameters, Argon2Type.Argon2id, 24)).IsFalse();
			await Assert.That(Argon2PasswordHasher.NeedsRehash(encoded, parameters, Argon2Type.Argon2id)).IsTrue();
			await Assert.That(Argon2PasswordHasher.NeedsRehash(encoded, parameters, Argon2Type.Argon2i, 24)).IsTrue();
			await Assert.That(Argon2PasswordHasher.NeedsRehash(encoded, parameters, Argon2Type.Argon2d, 24)).IsTrue();
			await Assert.That(Argon2PasswordHasher.NeedsRehash(encoded, new Argon2Parameters(72, 2, 2), Argon2Type.Argon2id, 24)).IsTrue();
			await Assert.That(Argon2PasswordHasher.NeedsRehash(encoded, new Argon2Parameters(64, 3, 2), Argon2Type.Argon2id, 24)).IsTrue();
			await Assert.That(Argon2PasswordHasher.NeedsRehash(encoded, new Argon2Parameters(64, 2, 1), Argon2Type.Argon2id, 24)).IsTrue();
		}
	}

	[Test]
	public async Task AcceptsBoundaryStrings()
	{
		// An 8-byte salt and a 4-byte hash, the shortest allowed.
		const string shortest = "$argon2d$v=19$m=8,t=1,p=1$AAAAAAAAAAA$AAAAAA";
		const string largest = "$argon2id$v=19$m=2147483647,t=2147483647,p=16777215$AAAAAAAAAAA$AAAAAA";

		using (Assert.Multiple())
		{
			await Assert.That(Argon2PasswordHasher.NeedsRehash(shortest, new Argon2Parameters(8, 1, 1), Argon2Type.Argon2d, 4)).IsFalse();
			await Assert.That(Argon2PasswordHasher.Verify("password"u8, shortest)).IsFalse();
			await Assert.That(Argon2PasswordHasher.NeedsRehash(largest, new Argon2Parameters(int.MaxValue, int.MaxValue, (1 << 24) - 1), Argon2Type.Argon2id, 4)).IsFalse();
		}
	}

	[Test]
	public async Task FormatsTheLargestParameters()
	{
		Argon2Parameters parameters = new(int.MaxValue, int.MaxValue, (1 << 24) - 1);
		byte[] salt = CreateDeterministicSource(16);
		byte[] hash = CreateDeterministicSource(32);

		await Assert.That(Argon2PhcString.Format(Argon2Type.Argon2id, parameters, salt, hash)).IsEqualTo($"$argon2id$v=19$m=2147483647,t=2147483647,p=16777215${ToBase64(salt)}${ToBase64(hash)}");
	}

	[Test]
	// Truncated or misplaced separators, like the error cases of test.c.
	[Arguments("")]
	[Arguments("$")]
	[Arguments("argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQwWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA$")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA$c29tZXNhbHQ")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA\n")]
	[Arguments(" $argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	// Unknown or differently written algorithm names.
	[Arguments("$argon2$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2x$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2di$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$Argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2I$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$scrypt$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	// A missing or unsupported version; the reference implementation reads a missing one as 16.
	[Arguments("$argon2i$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=16$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=20$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=019$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=+19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$V=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	// Missing, reordered, extra or malformed parameters.
	[Arguments("$argon2i$v=19$m=65536,t=2$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$t=2,m=65536,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1,keyid=AAAA$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1,data=AAAA$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1$keyid=AAAA$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=065536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=-65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=65536 ,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1.0$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=６５５３６,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	// Parameters out of range.
	[Arguments("$argon2i$v=19$m=7,t=1,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=15,t=1,p=2$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=65536,t=0,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=0$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=2147483647,t=2,p=16777216$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=2147483648,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=65536,t=4294967295,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=99999999999999999999,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	// A salt shorter than 8 bytes or a hash shorter than 4 bytes; test.c checks the empty salt.
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1$$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbA$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$AAAA")]
	// Invalid Base64: padding, other alphabets, whitespace, non-ASCII characters, impossible lengths and nonzero unused bits.
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ=$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA=")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj-qf_YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj.qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNh bHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtŁ")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtＡ")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbt\0")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQAA$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHR$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtA")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtB")]
	[Arguments("$argon2i$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$wWKIMhR9lyDFvRz9YTZweHKfbftvj+qf+YFY4NeBbtAAA")]
	public async Task RejectsInvalidStrings(string encoded)
	{
		using (Assert.Multiple())
		{
			await Assert.That(() => Argon2PasswordHasher.Verify("password"u8, encoded)).ThrowsExactly<FormatException>();
			await Assert.That(() => Argon2PasswordHasher.NeedsRehash(encoded, new Argon2Parameters(65536, 2, 1), Argon2Type.Argon2i)).ThrowsExactly<FormatException>();
		}
	}

	[Test]
	public async Task RejectsInvalidArguments()
	{
		Argon2Parameters parameters = new(8, 1, 1);
		byte[] salt = CreateDeterministicSource(8);

		using (Assert.Multiple())
		{
			await Assert.That(() => Argon2PasswordHasher.Hash("password"u8, parameters, Argon2Type.Argon2id, saltLength: 7)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("saltLength");
			await Assert.That(() => Argon2PasswordHasher.Hash("password"u8, parameters, Argon2Type.Argon2id, hashLength: 3)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("hashLength");
			await Assert.That(() => Argon2PasswordHasher.Hash("password"u8, parameters, (Argon2Type)3)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("type");
			await Assert.That(() => Argon2PasswordHasher.Hash("password"u8, default, Argon2Type.Argon2id)).ThrowsExactly<ArgumentException>().WithParameterName("parameters");
			await Assert.That(() => Argon2PasswordHasher.Hash("password"u8, salt.AsSpan(1), parameters, Argon2Type.Argon2id)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("salt");
			await Assert.That(() => Argon2PasswordHasher.Hash("password"u8, salt, parameters, Argon2Type.Argon2id, 3)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("hashLength");
			await Assert.That(() => Argon2PasswordHasher.Hash("password"u8, salt, parameters, (Argon2Type)(-1))).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("type");
			await Assert.That(() => Argon2PasswordHasher.Hash("password"u8, salt, default, Argon2Type.Argon2id)).ThrowsExactly<ArgumentException>().WithParameterName("parameters");
			await Assert.That(() => Argon2PasswordHasher.NeedsRehash(SmallReferenceString, parameters, Argon2Type.Argon2i, 3)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("hashLength");
			await Assert.That(() => Argon2PasswordHasher.NeedsRehash(SmallReferenceString, parameters, (Argon2Type)3)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("type");
			await Assert.That(() => Argon2PasswordHasher.NeedsRehash(SmallReferenceString, default, Argon2Type.Argon2i)).ThrowsExactly<ArgumentException>().WithParameterName("parameters");
		}
	}

	private static byte[] FromBase64(string value)
	{
		return Convert.FromBase64String(value.PadRight(value.Length + (4 - value.Length % 4) % 4, '='));
	}

	private static string ToBase64(byte[] value)
	{
		return Convert.ToBase64String(value).TrimEnd('=');
	}
}
