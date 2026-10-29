using System.Numerics;
using static CryptoBase.Tests.EllipticCurves.ECTestUtils;

namespace CryptoBase.Tests.EllipticCurves;

public class ECKeyTest
{
	private const int Iterations = 4;

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task ImportPrivateKeyTakesOneToNMinusOne(CurveCase curve)
	{
		ECReference reference = curve.Reference;
		BigInteger n = curve.Order;
		List<string> failures = [];

		foreach (BigInteger d in (BigInteger[])[1, 2, n - 2, n - 1, 1 + ECReference.RandomBelow(new Random(1), n - 1)])
		{
			KeyCase key = curve.NewKey();
			byte[] source = curve.EncodeScalar(d);

			if (!key.TryImportPrivateKey(source) || !key.HasPrivateKey || !key.HasPublicKey)
			{
				failures.Add($"{d:X} was rejected");
				continue;
			}

			CurvePoint q = reference.PublicKey(d);

			if (key.PrivateScalar != d || key.PublicPoint != q || !key.ExportPrivateKey().AsSpan().SequenceEqual(source) || !key.ExportPublicKey().AsSpan().SequenceEqual(curve.EncodePoint(q)))
			{
				failures.Add($"{d:X} gave {key.PrivateScalar:X} and {Show(key.PublicPoint)}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task ImportPrivateKeyRejectsEverythingElse(CurveCase curve)
	{
		BigInteger n = curve.Order;
		int length = curve.ScalarLength;
		List<string> failures = [];
		List<(string Name, byte[] Source)> cases =
		[
			("0", curve.EncodeScalar(0)),
			("n", curve.EncodeScalar(n)),
			("n + 1", curve.EncodeScalar(n + 1)),
			("all 0xFF", [.. Enumerable.Repeat((byte)0xFF, length)]),
			("empty", []),
		];

		foreach (int wrongLength in (int[])[1, length - 1, length + 1])
		{
			cases.Add(($"1 in {wrongLength} bytes", CurveCase.EncodeInteger(1, wrongLength)));
		}

		foreach ((string name, byte[] source) in cases)
		{
			KeyCase key = curve.NewKey();
			key.GenerateKey();

			if (key.TryImportPrivateKey(source) || key.HasPrivateKey || key.HasPublicKey || key.Storage().Any(static b => b is not 0))
			{
				failures.Add(name);
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task GenerateKeyDrawsAgainOutsideTheRange(CurveCase curve)
	{
		BigInteger n = curve.Order;
		int length = curve.ScalarLength;
		BigInteger d = n / 3;
		byte[] withHighBits = curve.EncodeScalar(d);
		withHighBits[0] |= (byte)~(0xFF >> 8 * length - curve.ScalarBitLength);
		Queue<byte[]> candidates = new([curve.EncodeScalar(0), curve.EncodeScalar(n), [.. Enumerable.Repeat((byte)0xFF, length)], withHighBits, curve.EncodeScalar(1)]);
		List<int> lengths = [];
		KeyCase key = curve.NewKey();

		key.GenerateKey(destination =>
		{
			lengths.Add(destination.Length);
			candidates.Dequeue().CopyTo(destination);
		});

		using (Assert.Multiple())
		{
			await Assert.That(lengths).IsEquivalentTo([length, length, length, length], CollectionOrdering.Matching);
			await Assert.That(key.PrivateScalar).IsEqualTo(d);
			await Assert.That(key.PublicPoint).IsEqualTo(curve.Reference.PublicKey(d));
		}
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task GenerateKeyKeepsTheKeyWhenFillThrows(CurveCase curve)
	{
		KeyCase generated = curve.NewKey();
		generated.GenerateKey();

		foreach (KeyCase key in (KeyCase[])[generated, curve.NewKey()])
		{
			byte[] storage = key.Storage();
			int calls = 0;

			using (Assert.Multiple())
			{
				await Assert.That(() => key.GenerateKey(destination =>
				{
					if (calls++ > 0)
					{
						throw new InvalidOperationException();
					}

					destination.Clear();
				})).ThrowsExactly<InvalidOperationException>();
				await Assert.That(calls).IsEqualTo(2);
				await Assert.That(key.Storage()).IsEquivalentTo(storage, CollectionOrdering.Matching);
			}
		}
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task GenerateKeyGivesAKeyPair(CurveCase curve)
	{
		HashSet<BigInteger> privateKeys = [];

		for (int i = 0; i < Iterations; ++i)
		{
			KeyCase key = curve.NewKey();
			key.GenerateKey();
			BigInteger d = key.PrivateScalar;

			using (Assert.Multiple())
			{
				await Assert.That(key.HasPrivateKey).IsTrue();
				await Assert.That(key.HasPublicKey).IsTrue();
				await Assert.That(d > 0 && d < curve.Order).IsTrue();
				await Assert.That(key.PublicPoint).IsEqualTo(curve.Reference.PublicKey(d));
				await Assert.That(privateKeys.Add(d)).IsTrue();
			}
		}
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task ExportedKeysImportAgain(CurveCase curve)
	{
		KeyCase key = curve.NewKey();
		key.GenerateKey();
		byte[] publicKey = key.ExportPublicKey();
		KeyCase fromPrivateKey = curve.NewKey();
		KeyCase fromPublicKey = curve.NewKey();

		using (Assert.Multiple())
		{
			await Assert.That(fromPrivateKey.TryImportPrivateKey(key.ExportPrivateKey())).IsTrue();
			await Assert.That(fromPrivateKey.ExportPublicKey()).IsEquivalentTo(publicKey, CollectionOrdering.Matching);
			await Assert.That(fromPublicKey.TryImportPublicKey(publicKey)).IsTrue();
			await Assert.That(fromPublicKey.HasPrivateKey).IsFalse();
			await Assert.That(fromPublicKey.HasPublicKey).IsTrue();
			await Assert.That(fromPublicKey.PublicPoint).IsEqualTo(key.PublicPoint);
			await Assert.That(fromPublicKey.ExportPublicKey()).IsEquivalentTo(publicKey, CollectionOrdering.Matching);
		}
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task ImportPublicKeyRejectsPointsOffTheCurve(CurveCase curve)
	{
		List<string> failures = [];

		foreach ((string name, byte[] source) in InvalidPeerKeys(curve))
		{
			KeyCase key = curve.NewKey();
			key.GenerateKey();

			if (key.TryImportPublicKey(source) || key.HasPrivateKey || key.HasPublicKey || key.Storage().Any(static b => b is not 0))
			{
				failures.Add(name);
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task MissingKeysThrow(CurveCase curve)
	{
		byte[] g = curve.EncodePoint(curve.Reference.Generator);
		KeyCase empty = curve.NewKey();
		KeyCase publicOnly = curve.NewKey();
		_ = publicOnly.TryImportPublicKey(g);

		using (Assert.Multiple())
		{
			await Assert.That(() => empty.ExportPublicKey()).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => publicOnly.ExportPrivateKey()).ThrowsExactly<InvalidOperationException>();
			await Assert.That(() => publicOnly.DeriveSharedSecret(g)).ThrowsExactly<InvalidOperationException>();
		}
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task DestinationsMayBeLonger(CurveCase curve)
	{
		KeyCase key = curve.NewKey();
		key.GenerateKey();
		byte[] peer = curve.EncodePoint(curve.Reference.Generator);
		byte[] privateKey = [.. new byte[key.PrivateKeyLength], 0xA5];
		byte[] publicKey = [.. new byte[key.PublicKeyLength], 0xA5];
		byte[] sharedSecret = [.. new byte[key.SharedSecretLength], 0xA5];

		using (Assert.Multiple())
		{
			await Assert.That(key.ExportPrivateKey(privateKey)).IsEqualTo(key.PrivateKeyLength);
			await Assert.That(privateKey).IsEquivalentTo((byte[])[.. curve.EncodeScalar(key.PrivateScalar), 0xA5], CollectionOrdering.Matching);
			await Assert.That(key.ExportPublicKey(publicKey)).IsEqualTo(key.PublicKeyLength);
			await Assert.That(publicKey).IsEquivalentTo((byte[])[.. curve.EncodePoint(key.PublicPoint), 0xA5], CollectionOrdering.Matching);
			await Assert.That(key.TryDeriveSharedSecret(peer, sharedSecret)).IsTrue();
			await Assert.That(sharedSecret).IsEquivalentTo((byte[])[.. curve.EncodeCoordinate(key.PublicPoint.X), 0xA5], CollectionOrdering.Matching);
			await Assert.That(() => key.ExportPrivateKey(new byte[key.PrivateKeyLength - 1])).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
			await Assert.That(() => key.ExportPublicKey(new byte[key.PublicKeyLength - 1])).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
			await Assert.That(() => key.TryDeriveSharedSecret(peer, new byte[key.SharedSecretLength - 1])).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("destination");
		}
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task SharedSecretIsTheXOfTheProduct(CurveCase curve)
	{
		ECReference reference = curve.Reference;
		BigInteger n = curve.Order;
		Random random = new(2);
		List<(BigInteger, BigInteger)> pairs = [(1, 1), (1, n - 1), (n - 1, n - 1)];
		List<string> failures = [];

		for (int i = 0; i < Iterations; ++i)
		{
			pairs.Add((1 + ECReference.RandomBelow(random, n - 1), 1 + ECReference.RandomBelow(random, n - 1)));
		}

		foreach ((BigInteger a, BigInteger b) in pairs)
		{
			KeyCase left = curve.NewKey();
			KeyCase right = curve.NewKey();
			_ = left.TryImportPrivateKey(curve.EncodeScalar(a));
			_ = right.TryImportPrivateKey(curve.EncodeScalar(b));
			byte[] expected = curve.EncodeCoordinate(reference.PublicKey(a * b % n).X);

			if (left.DeriveSharedSecret(right.ExportPublicKey()) is not { } fromLeft || !fromLeft.AsSpan().SequenceEqual(expected)
				|| right.DeriveSharedSecret(left.ExportPublicKey()) is not { } fromRight || !fromRight.AsSpan().SequenceEqual(expected))
			{
				failures.Add($"{a:X} and {b:X}");
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task SharedSecretRejectsPointsOffTheCurve(CurveCase curve)
	{
		KeyCase key = curve.NewKey();
		key.GenerateKey();
		byte[] untouched = [.. Enumerable.Repeat((byte)0xA5, key.SharedSecretLength)];
		List<string> failures = [];

		foreach ((string name, byte[] peer) in InvalidPeerKeys(curve))
		{
			byte[] destination = [.. untouched];

			if (key.TryDeriveSharedSecret(peer, destination) || !destination.AsSpan().SequenceEqual(untouched))
			{
				failures.Add(name);
			}
		}

		await Assert.That(failures).IsEmpty();
	}

	[Test]
	[MethodDataSource(typeof(CurveCase), nameof(CurveCase.All))]
	public async Task ClearErasesTheKey(CurveCase curve)
	{
		KeyCase key = curve.NewKey();
		key.GenerateKey();
		bool heldKey = key.Storage().Any(static b => b is not 0);
		key.Clear();

		using (Assert.Multiple())
		{
			await Assert.That(heldKey).IsTrue();
			await Assert.That(key.HasPrivateKey).IsFalse();
			await Assert.That(key.HasPublicKey).IsFalse();
			await Assert.That(key.Storage().All(static b => b is 0)).IsTrue();
		}
	}

	private static IEnumerable<(string Name, byte[] Encoding)> InvalidPeerKeys(CurveCase curve)
	{
		CurvePoint g = curve.Reference.Generator;
		byte[] encoding = curve.EncodePoint(g);
		yield return ("empty", []);
		yield return ("the compressed form", [(byte)(g.Y.IsEven ? 0x02 : 0x03), .. curve.EncodeCoordinate(g.X)]);
		yield return ("prefix 0x06", [0x06, .. encoding.AsSpan(1)]);
		yield return ("(x, y + 1)", curve.EncodePoint(g with { Y = curve.Reference.Mod(g.Y + 1) }));
	}
}
