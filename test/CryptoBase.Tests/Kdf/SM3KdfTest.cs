using CryptoBase.Kdf;
using static CryptoBase.Tests.EllipticCurves.SM9.SM9Vectors;
using static CryptoBase.Tests.SM2.SM2TestUtils;

namespace CryptoBase.Tests.Kdf;

public class SM3KdfTest
{
	// The keys that the examples of the standards print, from the inputs that they print: GB/T 32918.5-2017, C.2, t = KDF(x2 ‖ y2, klen) of the encryption, and B.2, K = KDF(xU ‖ yU ‖ ZA ‖ ZB, 128) of the key exchange; GM/T 0044.5-2016, C.2, K = KDF(C ‖ w ‖ IDB, 256) of the key encapsulation, D.2, K = KDF(C1 ‖ w ‖ IDB, 416) of the encryption, and B.2, SK = KDF(IDA ‖ IDB ‖ RA ‖ RB ‖ g1 ‖ g2 ‖ g3, 128) of the key exchange.
	[Test]
	public async Task KeysOfTheStandardExamples()
	{
		byte[] alice = "Alice"u8.ToArray();
		byte[] bob = "Bob"u8.ToArray();
		(byte[] Secret, byte[] Key)[] examples =
		[
			(Hex("335E18D7 51E51F04 0E27D468 138B7AB1 DC86AD7F 981D7D41 6222FD6A B3ED230D AB743EBC FB22D64F 7B6AB791 F70658F2 5B48FA93 E54064FD BFBED3F0 BD847AC9"), Hex("44E60FDB F0BAE814 37665374 BEF26749 046C9E")),
			(Hex("C558B44B EE5301D9 F52B44D9 39BB5958 4D75B903 4DD6A9FC 82687210 9A65739F 3252B35B 191D8AE0 1CD122C0 25204334 C5EACF68 A0CB4854 C6A7D367 ECAD4DE7 3B85A571 79E11E7E 513AA622 991F2CA7 4D1807A0 BD4D4B38 F90987A1 7AC245B1 79C988D6 3229D97E F19FE02C A1056E01 E6A7411E D24694AA 8F834F4A 4AB022F7"), Hex("6C893473 54DE2484 C60B4AB1 FDE4C6E5")),
			([.. Hex($"{EncapsulateCX} {EncapsulateCY} {EncapsulateW}"), .. bob], Hex("4FF5CF86 D2AD40C8 F4BAC98D 76ABDBDE 0C0E2F0A 829D3F91 1EF5B2BC E0695480")),
			([.. Hex($"{EncryptC1X} {EncryptC1Y} {EncryptW}"), .. bob], Hex("58373260 F067EC48 667C21C1 44F8BC33 CD304978 8651FFD5 F738003E 51DF3117 4D0E4E40 2FD87F45 81B612F7 4259DB57 4F67ECE6")),
			([.. alice, .. bob, .. Hex($"{ExchangePointAX} {ExchangePointAY} {ExchangePointBX} {ExchangePointBY} {ExchangeG1} {ExchangeG2} {ExchangeG3}")], Hex("68B20D30 77EA6E2B 82531583 6FDBC633")),
		];
		List<int> failures = [];

		for (int i = 0; i < examples.Length; ++i)
		{
			byte[] key = new byte[examples[i].Key.Length];
			SM3Kdf.DeriveKey(examples[i].Secret, key);

			if (!key.AsSpan().SequenceEqual(examples[i].Key))
			{
				failures.Add(i);
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// Keys of 1 byte to 41 blocks, around the groups of vector lanes, against the blocks SM3(Z ‖ ct) one at a time, for an empty Z, Z around the padding of one and two blocks and the counter across them, and a Z of many blocks.
	[Test]
	public async Task KeysMatchSingleBlocks()
	{
		const int MaxBlocks = 41;
		List<string> failures = [];

		foreach (int zLength in (int[])[0, 1, 51, 52, 59, 60, 61, 63, 64, 703])
		{
			byte[] z = [.. Enumerable.Range(0, zLength).Select(static i => (byte)(i * 73 + 9))];
			byte[] expected = new byte[32 * MaxBlocks];
			SM3KdfState kdf = default;
			kdf.Initialize();
			kdf.Append(z);

			for (int i = 0; i < MaxBlocks; ++i)
			{
				kdf.WriteBlock((uint)i + 1, expected.AsSpan(32 * i));
			}

			kdf.Clear();

			for (int length = 1; length <= expected.Length; ++length)
			{
				byte[] key = new byte[length];
				SM3Kdf.DeriveKey(z, key);

				if (!key.AsSpan().SequenceEqual(expected.AsSpan(0, length)))
				{
					failures.Add($"Z of {zLength} bytes, a key of {length} bytes");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	// The secret may lie anywhere in the output, before its start, after it or across its end, and the key is the same.
	[Test]
	public async Task SecretMayOverlapTheOutput()
	{
		byte[] secret = [.. Enumerable.Range(0, 100).Select(static i => (byte)(i * 31 + 7))];
		List<string> failures = [];

		foreach (int length in (int[])[1, 32, 100, 160, 1000])
		{
			byte[] expected = new byte[length];
			SM3Kdf.DeriveKey(secret, expected);

			foreach (int shift in (int[])[-150, -40, 0, 40, 150])
			{
				byte[] buffer = new byte[1500];
				int secretOffset = 200;
				int outputOffset = secretOffset + shift;
				secret.CopyTo(buffer, secretOffset);
				SM3Kdf.DeriveKey(buffer.AsSpan(secretOffset, secret.Length), buffer.AsSpan(outputOffset, length));

				if (!buffer.AsSpan(outputOffset, length).SequenceEqual(expected))
				{
					failures.Add($"a key of {length} bytes, {shift} bytes from the secret");
				}
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	public async Task EmptyOutputThrows()
	{
		await Assert.That(static () => SM3Kdf.DeriveKey("secret"u8, Span<byte>.Empty)).ThrowsExactly<ArgumentOutOfRangeException>();
	}
}
