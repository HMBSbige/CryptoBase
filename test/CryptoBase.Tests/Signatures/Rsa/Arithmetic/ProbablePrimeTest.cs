using CryptoBase.Signatures.Rsa;
using CryptoBase.Signatures.Rsa.Arithmetic;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Reflection;
using System.Security.Cryptography;
using static CryptoBase.Signatures.Rsa.Arithmetic.ProbablePrime;
using static CryptoBase.Tests.Signatures.Rsa.Arithmetic.RsaArithmeticTestUtils;

namespace CryptoBase.Tests.Signatures.Rsa.Arithmetic;

// ProbablePrime.Search on scripted candidates, which pass or fail the tests before Miller-Rabin, or are drawn again, as the script says: whether the platform tests two at once or not, the prime it keeps and the failures that make it give up are those of testing one candidate after the other. Two lengths, of which every platform takes pairs at one at least and some take none at one.
internal class ProbablePrimeTest
{
	// ProbablePrime.Candidate, which the tests cannot name.
	[DynamicallyAccessedMembers(DynamicallyAccessedMemberTypes.PublicFields | DynamicallyAccessedMemberTypes.NonPublicFields | DynamicallyAccessedMemberTypes.NonPublicProperties)]
	private static readonly Type CandidateType = Type.GetType("CryptoBase.Signatures.Rsa.Arithmetic.ProbablePrime+Candidate, CryptoBase", true) ?? throw new TypeLoadException();

	// Primes and composites of each length of Lengths, whose top two bits are set as those of the candidates are: the first that Miller-Rabin on BigInteger kept, after 40 rounds, or rejected, from the seeds 91 to 93 and 95 to 102.
	private static readonly BigInteger[] Primes1024 =
	[
		Hex("CC87A0126CADC5507115BF1C99BFDA434D6E93519CBAA434C1CFDD41FC87951F1E58FD58E9F3C56187B8BAB722006B37393A7F41A3D51249DF8A06310F4D092CCCE21D05F6137ECDAF3726AF0384BEC801EC8F05B361013B5DF46C67C17598AE67BE3BE1C86C23C94033A3A511703D4BF2C7A6A8FB70EB08C3E5721ADCBE0053"),
		Hex("C6A860122E4E3C75F39AD8587CD1E1869BB0F9A4BBB45ED3C8FBB84FCAB92F5F1357CF865B3E9D4B52B26377E2D5DA866CDCBD77DA5942D62FBB50CB9A8F285712BB2D56574E635927D4FDFE8A8D8E19C753DFF210411B41AE27D4BE97C5204FB0EE0571EEA1D94CCFCEB9F59AF1FE037AE891BBDED945172C1CF8319A3327E1"),
		Hex("C9354EC0315AFDA349E79B1928E3CE0D007EE46DF2BFD3D22C28ADF48E82422B6A5985C35CFA322ABDE0E71835D5404034B99358FAABACCFF9AABA6385BB8331FFD1EE682402C693D7DF199F8FCD7CE78B33AF12B342FC58C2AAC6228D0A0AD78077E5B2BCCC74E3CB469AF7046E79C0CD486D8F9204A8E584AA3598E691D973")
	];

	private static readonly BigInteger[] Composites1024 =
	[
		Hex("E1F011AF55170712F0E053AE3ABBCD0E309E2292C0B7C69313EA2191A2BF5F19E602ACE814E0DF6BC9AB96F9A8AF56B2303D8734D382474DD8268F3582D1BE87DAFB5D906EFD4BB7D3F61407049FB9A31FA3626047391544931AE66097B261DEB39B9861527656939ECE6EE8C7DB67BE8727E7E3AF7222725DB007C590EA8541"),
		Hex("EB166FFE716E078A11221156E7BC11F8D465B2265BF8EB3F590CB7A98C24BF1E8A9410C71687AEE5E73A82B629BD8A707CF0DE376B22B07BDE85852054EFC594D93A13712C8DE8B29C1D490C73C9C4DE2C0B9951B899599E063C55FE394B033046F680EE9CB77C164196D0C4C0B7B83483BF6B57200C8A5928AF29A8A429486D"),
		Hex("F53CCC4C8DC507023264CFFD94BC55E1782B41BBF6390FEB9E2E4EC276881F232E2674A7172E7D6006C86E74AACCBE2DC8A2353A03C11AAAE4E47A0B250DCBA1D879C952EA1E84AD65447D11E3F3D0193974D04229F89DF7795EC59CDBE3A583DA51687AE5F8A199E45E32A0B99309A98056EECB91A5F340F4AF4B8CB7690C99"),
		Hex("FF62299BA91B087A53A58DA441BD98CB1CF2D04F927A3398E450E5DA60EC8028D2B7D98619D44CDB24575A322BDAF2EA15558C3C9A6183D8E94370F6F72CD2AED8B87F34A7AE21A92F6BB115521DDB5446DC07329A58E151EB81353A7E7B47D56DAD50062F39C71C8826947CB36F591F7DEE723F013F5B28BFAE6D6FCAA9CFC3"),
		Hex("C98987EAC57208F274E74B4CEEBDDCB4C0B860E42DBB584429727BF34A50E02E76493D661A7B1B5642E546EFACE926A86108E33F3201ED07EFA166E1C94AD8BBD7F83515653EBDA4F893E51AC247E68F54453D230BB726AB5EA3A4D82014E92800083792797AED9F2BEEF758AC4BAA947986F5B272D9C30F8BAE8F52DDE892EF"),
		Hex("D3AFE439E1C9086A952909F39CBE209E647FEF79C8FC7CF06F94120B34B440331ADAA1461C22EAD1607432AD2DF75965ADBB3A42CAA05635F5005BCC9A69DFC8D637EBF623CE599FC1BA191F3172F1CA61AD74137C176A05D0C51475C2AC8B7A93641F1FC2BA1222CEB65935A627FA09761D7926E3722CF656ADB036F028561B"),
		Hex("DDD54187FE2008E2B66AC79A49BE648709467E0D633DA19DB4B5A9241E18A038BE6C06251DC9BA4C7E031E6BAE068D22F96E91446240C063FB5F51B86C87E5D5D676A0D7E15EF69A8AE14E24A19CFC066E15AB04ED76AE5F43E7841364442DCC27BF07AB0CFB38A5727FBB119F034B7F73B5FD9A540C94DD22ADD21904681947"),
		Hex("E7FB9FD61A77085AD7AC8541F6BFA871AD0C0EA2FF7EC549F9D73F3C087C013D62FD6A051F7089C69D910A283014C1E04620E847FADF299200BE47A33EA5ECE2D5B556B89FEE92955408822810C607417B7EE2F45ED6F3B8B509F3B106DDCF1FBA1AEF37553C5E2815471DED98DF9CF46F4D800DC5A6FCC4EDACF4FD17A8DC73")
	];

	private static readonly BigInteger[] Primes1536 =
	[
		Hex("F7E8A7757EA84EFBC4C86FA3114D1953320096638A5FE11E7B092820CA7947F23703A20DDB1DFCD0388203F780EC2332B773E664246858D9F582927A79877EC8BFEF8F357FD0C71964BACBE239D7A00E83A2A7494207E2C73822DDA236618B03653DCE21FAA7D55FBC296B062F90FCD325C8DB058BE3068E118ADC542F8442D0C1FA7336AAC6D75FA8332D4895F35115770D2678314DFED87379E7D2067D92E97101FA81A573E14C410D5289BC7907F85CE2D1C26DB3D1BC7B19A98C12186CFB"),
		Hex("CF2F67340AEF27D5E1C5E73F9C0CC8A6067B5E4679292AD30A00AF6D30378E746674042F88A98B6D486BF14A7609E2D254EDAEB3F437A5145FF0DD965D7041D30F5E487EDF1C93B52E537E1E3D89C3E7960DDD710B9ED2AFF3E34C1C5EB9C1C78A2FD33AF178DF325EB951C7E798F8AB0C3B4F1E37CC02E29839F7BE4EF26F7F1A65B73535D023E62C153D0E806BE9EAA29B0ECD39DC2C4265080A145E0B479CC7D232D0839A461B0989FA630E68EBA24E55CA958F37514D353AD07CEB2C6F27"),
		Hex("C090B9EA36DEE6727F6C36A111D48CE9F60D6632D68C22E21EA1B7B98A2F35706914D84BA4E7A4054A53876A18655130CEE758AB972B53D9DB5ED1DBE430C506D64E0662045BD14EB8FD5E2A65FE41F07D9CEA4F360BBF6F76DDA676365D03A87DED695955CECCB8378EB6569ACAB682D50838E8D942F43FA85B31D11408DD6F54F9F51C8116F8B584C3922A4B67CAA8AFBA7F13CC57A1730AEA704D84517CCAB802BE6472663D541B05407BB6FE2919A8B52390D39671125E6883BE6B14BAC5")
	];

	private static readonly BigInteger[] Composites1536 =
	[
		Hex("D688150BF757F3647BB0D50BFF14CFD02710AE3E13CE292E7369C969F67B16D681649509898FCF7EC637C8F01B06AF414837EBDF32149B6B919F9BC7D5B99C44A1F011AF55170712F0E053AE3ABBCD0E309E2292C0B7C69313EA2191A2BF5F19E602ACE814E0DF6BC9AB96F9A8AF56B2303D8734D382474DD8268F3582D1BE87DAFB5D906EFD4BB7D3F61407049FB9A31FA3626047391544931AE66097B261DEB39B9861527656939ECE6EE8C7DB67BE8727E7E3AF7222725DB007C590EA8541"),
		Hex("E26E3062A7DA3E636F165F514B283A46AC875627F169033E941AED658E3F8DD4D05B9B49A201129C0D34AD54B61DB24933C1DE8ACBE9647DB8D263B9774C971C6B166FFE716E078A11221156E7BC11F8D465B2265BF8EB3F590CB7A98C24BF1E8A9410C71687AEE5E73A82B629BD8A707CF0DE376B22B07BDE85852054EFC594D93A13712C8DE8B29C1D490C73C9C4DE2C0B9951B899599E063C55FE394B033046F680EE9CB77C164196D0C4C0B7B83483BF6B57200C8A5928AF29A8A429486D"),
		Hex("EE554CB9575E8A62627CEA96973BA5BD30FDFF10CF04DD4EB5CB1162270203D21F51A089BA7355BB543091B85235B5521F4AD23564BE2D8FDF062CAC1ADF93F4353CCC4C8DC507023264CFFD94BC55E1782B41BBF6390FEB9E2E4EC276881F232E2674A7172E7D6006C86E74AACCBE2DC8A2353A03C11AAAE4E47A0B250DCBA1D879C952EA1E84AD65447D11E3F3D0193974D04229F89DF7795EC59CDBE3A583DA51687AE5F8A199E45E32A0B99309A98056EECB91A5F340F4AF4B8CB7690C99"),
		Hex("FB3C670F07E2D66156E374DBE34F1133B573A7FAAEA0B75ED57C355EC0C57AD16E48A6C9D2E598DA9B2D751CEE4DB85A0AD4C5E0FE93F6A1053AF59FBC718FCCFF62299BA91B087A53A58DA441BD98CB1CF2D04F927A3398E450E5DA60EC8028D2B7D98619D44CDB24575A322BDAF2EA15558C3C9A6183D8E94370F6F72CD2AED8B87F34A7AE21A92F6BB115521DDB5446DC07329A58E151EB81353A7E7B47D56DAD50062F39C71C8826947CB36F591F7DEE723F013F5B28BFAE6D6FCAA9CFC3"),
		Hex("C7238266B76622604949FF212F627CAA3AE94FE38C3B916EF62E595B5989F1CFBD3FAC09EB57DBF8E22A5A808965BB62F65DB88B9768BFB32C6EBE925F048AA4C98987EAC57208F274E74B4CEEBDDCB4C0B860E42DBB584429727BF34A50E02E76493D661A7B1B5642E546EFACE926A86108E33F3201ED07EFA166E1C94AD8BBD7F83515653EBDA4F893E51AC247E68F54453D230BB726AB5EA3A4D82014E92800083792797AED9F2BEEF758AC4BAA947986F5B272D9C30F8BAE8F52DDE892EF"),
		Hex("D30A9EBD66E96E5F3DAF89667B76E720BE5FF8CC6AD66B7E17DF7E58F24C68CD0C35B24803C91E1729263EE3257DBD6BE1E7AB36303C88C553A186850197867B93AFE439E1C9086A952909F39CBE209E647FEF79C8FC7CF06F94120B34B440331ADAA1461C22EAD1607432AD2DF75965ADBB3A42CAA05635F5005BCC9A69DFC8D637EBF623CE599FC1BA191F3172F1CA61AD74137C176A05D0C51475C2AC8B7A93641F1FC2BA1222CEB65935A627FA09761D7926E3722CF656ADB036F028561B"),
		Hex("DFF0B913166DBA5E301514ACC78A539743D5A0B64871448F3890A2548B10DFCB5B2CB7881B3B613670232247C195C073CD719FE0CA1151D779D54F78A32A82535DD54187FE2008E2B66AC79A49BE648709467E0D633DA19DB4B5A9241E18A038BE6C06251DC9BA4C7E031E6BAE068D22F96E91446240C063FB5F51B86C87E5D5D676A0D7E15EF69A8AE14E24A19CFC066E15AB04ED76AE5F43E7841364442DCC27BF07AB0CFB38A5727FBB119F034B7F73B5FD9A540C94DD22ADD21904681947"),
		Hex("ECD7D56AC6F1055D247C9EF1129DBE0DC84C489F270C1E9F5941C65124D356C9AA23BDC834AEA454B72007AB5CADC37CB8FA928B63E61AE9A009186B46BD7D2B27FB9FD61A77085AD7AC8541F6BFA871AD0C0EA2FF7EC549F9D73F3C087C013D62FD6A051F7089C69D910A283014C1E04620E847FADF299200BE47A33EA5ECE2D5B556B89FEE92955408822810C607417B7EE2F45ED6F3B8B509F3B106DDCF1FBA1AEF37553C5E2815471DED98DF9CF46F4D800DC5A6FCC4EDACF4FD17A8DC73")
	];

	private static readonly Dictionary<int, (BigInteger[] Primes, BigInteger[] Composites)> Values = new()
	{
		[1024] = (Primes1024, Composites1024),
		[1536] = (Primes1536, Composites1536)
	};

	public static IEnumerable<int> Lengths()
	{
		yield return 1024;
		yield return 1536;
	}

	// Each script: its candidates as (index into the primes, or −1 − index into the composites, what becomes of it before Miller-Rabin), the limit of failures, and the prime expected, or −1 for FAILURE.
	// A candidate drawn again is a prime, which would be kept if it were tested.
	public static IEnumerable<Func<(int Bits, string Name, (int Candidate, CandidateOutcome Outcome)[] Script, int Limit, int Expected)>> Scripts()
	{
		const CandidateOutcome Pass = CandidateOutcome.Pass;
		const CandidateOutcome Fail = CandidateOutcome.Fail;
		const CandidateOutcome Redraw = CandidateOutcome.Redraw;

		foreach (int bits in Lengths())
		{
			yield return () => (bits, "the first candidate", [(0, Pass), (1, Pass)], 10, 0);
			yield return () => (bits, "the first of the second pair", [(-1, Pass), (-2, Pass), (0, Pass), (1, Pass)], 10, 0);
			yield return () => (bits, "the second of a pair", [(-1, Pass), (0, Pass), (1, Pass)], 10, 0);
			yield return () => (bits, "a prime that fails the tests before Miller-Rabin", [(0, Fail), (-1, Pass), (1, Pass), (2, Pass)], 10, 1);
			yield return () => (bits, "a prime after failures before Miller-Rabin", [(-1, Fail), (-2, Fail), (2, Pass), (0, Pass)], 10, 2);
			yield return () => (bits, "the first with the limit after it", [(0, Pass), (-1, Fail), (-2, Fail), (-3, Fail)], 2, 0);
			yield return () => (bits, "the second at the limit", [(-1, Pass), (0, Pass)], 2, 0);
			yield return () => (bits, "the limit before the second", [(-1, Pass), (0, Pass)], 1, -1);
			yield return () => (bits, "the limit in failures before Miller-Rabin", [(-1, Pass), (-2, Fail), (-3, Fail), (0, Pass)], 3, -1);
			yield return () => (bits, "the limit in composites", [(-1, Pass), (-2, Pass), (-3, Pass), (-4, Pass), (0, Pass)], 4, -1);
			yield return () => (bits, "the limit just after a prime", [(-1, Pass), (-2, Pass), (-3, Pass), (0, Pass), (-4, Pass)], 4, 0);
			yield return () => (bits, "a prime after ten times the limit drawn again", [.. Enumerable.Repeat((1, Redraw), 30), (0, Pass), (2, Pass)], 3, 0);
			yield return () => (bits, "a prime with failures short of the limit and draws again around them", [(1, Redraw), (-1, Fail), (1, Redraw), (1, Redraw), (-2, Fail), (1, Redraw), (0, Pass), (2, Pass)], 3, 0);
			yield return () => (bits, "draws again while the first of a pair is pending", [(-1, Pass), (1, Redraw), (1, Redraw), (0, Pass)], 2, 0);
			yield return () => (bits, "the limit in failures with draws again between them", [(-1, Fail), (1, Redraw), (-2, Fail), (1, Redraw), (-3, Pass), (0, Pass)], 3, -1);
		}
	}

	[Test]
	[MethodDataSource(nameof(Scripts))]
	[SuppressMessage("ReSharper", "AccessToDisposedClosure", Justification = "Assertions finish before disposal.")]
	public async Task KeepsWhatOneAfterTheOtherKeeps(int bits, string name, (int Candidate, CandidateOutcome Outcome)[] script, int limit, int expected)
	{
		(BigInteger[] primes, BigInteger[] composites) = Values[bits];
		int limbs = bits / 64;
		int next = 0;
		ulong[] result = new ulong[limbs];

		CandidateOutcome Source(Span<ulong> value, ReadOnlySpan<ulong> other)
		{
			if (next >= script.Length)
			{
				throw new InvalidOperationException($"{name}: the script ran out.");
			}

			(int candidate, CandidateOutcome outcome) = script[next++];
			ToLimbs(candidate >= 0 ? primes[candidate] : composites[-1 - candidate], limbs).CopyTo(value);
			return outcome;
		}

		using Search search = new(limbs, bits, Source);

		if (expected < 0)
		{
			await Assert.That(search.Find(result, default, limit)).IsFalse();
		}
		else
		{
			await Assert.That(search.Find(result, default, limit)).IsTrue();
			await Assert.That(ToBigInteger(result)).IsEqualTo(primes[expected]);
		}
	}

	// A search goes on from one prime to the next with the contexts of its slots, which take every candidate in turn, and passes the prime before to the source. Each search takes candidates of its own; the one after its prime may be drawn while the prime is pending, and is not kept.
	[Test]
	[MethodDataSource(nameof(Lengths))]
	[SuppressMessage("ReSharper", "AccessToModifiedClosure", Justification = "Source reads the candidates and the prime that each turn of the loop sets.")]
	public async Task FindsOnePrimeAfterAnother(int bits)
	{
		(BigInteger[] primes, BigInteger[] composites) = Values[bits];
		int limbs = bits / 64;
		Queue<BigInteger> candidates = [];
		BigInteger before = BigInteger.Zero;
		List<string> failures = [];

		CandidateOutcome Source(Span<ulong> value, ReadOnlySpan<ulong> other)
		{
			if ((other.IsEmpty ? BigInteger.Zero : ToBigInteger(other)) != before)
			{
				failures.Add($"other was not {before:X}");
			}

			ToLimbs(candidates.Dequeue(), limbs).CopyTo(value);
			return CandidateOutcome.Pass;
		}

		using Search search = new(limbs, bits, Source);
		BigInteger[][] scripts = [[composites[0], primes[0], composites[1]], [composites[2], composites[3], primes[1], composites[4]], [primes[2], composites[5]]];
		ulong[] previous = [];

		for (int i = 0; i < scripts.Length; ++i)
		{
			candidates = new Queue<BigInteger>(scripts[i]);
			ulong[] result = new ulong[limbs];

			if (!search.Find(result, previous, 10) || ToBigInteger(result) != primes[i])
			{
				failures.Add($"search {i} kept {ToBigInteger(result):X}");
			}

			previous = result;
			before = ToBigInteger(result);
		}

		await Assert.That(failures).IsEmpty();
	}

	// Dispose erases what the search keeps of its candidates, the last of which is the prime that it found: the values of each slot, the number of trailing zeros of w − 1, and the contexts, whose −n⁻¹ mod 2^DigitBits gives the low bits of w.
	[Test]
	[MethodDataSource(nameof(Lengths))]
	public async Task DisposeErasesTheCandidates(int bits)
	{
		BigInteger prime = Values[bits].Primes[0];
		int limbs = bits / 64;
		ulong[] result = new ulong[limbs];
		Search search = new(limbs, bits, (value, _) =>
		{
			ToLimbs(prime, limbs).CopyTo(value);
			return CandidateOutcome.Pass;
		});
		bool found = search.Find(result, default, 10);
		search.Dispose();
		List<string> failures = found ? [] : ["no prime was found"];

		foreach (string slot in (string[])["_first", "_second"])
		{
			object candidate = GetField(search, typeof(Search), slot) ?? throw new InvalidOperationException($"{slot} is null.");
			MontgomeryContext context = CandidateType.GetProperty("Context", BindingFlags.Instance | BindingFlags.NonPublic)?.GetValue(candidate) as MontgomeryContext ?? throw new InvalidOperationException($"{slot} has no context.");
			failures.AddRange(NonZeroWords(candidate, CandidateType).Concat(MontgomeryKernelCase.Of(context).NonZeroWords(context)).Select(field => $"{slot}: {field}"));

			if (GetField(candidate, CandidateType, "_a") is not 0)
			{
				failures.Add($"{slot}: _a");
			}
		}

		if (GetField(search, typeof(Search), "_pair") is MontgomeryPairContext pair)
		{
			failures.AddRange(MontgomeryPairKernelCase.All().Single(kernel => kernel.KernelType == pair.GetType().GetGenericArguments()[0]).NonZeroWords(pair).Select(field => $"_pair: {field}"));
		}

		await Assert.That(failures).IsEmpty();
	}

	// A run of Appendix A.1.3 that reaches a limit returns FAILURE, here at q, and Generate runs it again from the start with a new source, up to four runs: the next run searches p anew, and the search of q takes the p of its own run. After the fourth, Generate throws, with p and q zero.
	[Test]
	[Arguments(0)]
	[Arguments(1)]
	[Arguments(3)]
	[Arguments(4)]
	public async Task GenerateRunsAgainFromTheStart(int failingRuns)
	{
		const int Nlen = 2048;
		(BigInteger[] primes, _) = Values[Nlen / 2];
		int limbs = Nlen / 128;
		int runs = 0;
		// The p that each search of q is given, without repeats.
		List<BigInteger> others = [];
		ulong[] p = new ulong[limbs];
		ulong[] q = new ulong[limbs];

		// A failing run finds primes[2] for p and fails every candidate for q; the last finds primes[0] and primes[1].
		CandidateSource CreateSource()
		{
			bool fails = ++runs <= failingRuns;

			return (value, other) =>
			{
				if (!other.IsEmpty)
				{
					BigInteger before = ToBigInteger(other);

					if (others.Count is 0 || others[^1] != before)
					{
						others.Add(before);
					}

					if (fails)
					{
						return CandidateOutcome.Fail;
					}
				}

				ToLimbs(other.IsEmpty ? primes[fails ? 2 : 0] : primes[1], limbs).CopyTo(value);
				return CandidateOutcome.Pass;
			};
		}

		if (failingRuns < 4)
		{
			Generate(Nlen, p, q, CreateSource);
			BigInteger[] expectedOthers = failingRuns is 0 ? [primes[0]] : [primes[2], primes[0]];

			using (Assert.Multiple())
			{
				await Assert.That(runs).IsEqualTo(failingRuns + 1);
				await Assert.That((ToBigInteger(p), ToBigInteger(q))).IsEqualTo((primes[0], primes[1]));
				await Assert.That(others).IsEquivalentTo(expectedOthers, CollectionOrdering.Matching);
			}
		}
		else
		{
			await Assert.That(() => Generate(Nlen, p, q, CreateSource)).Throws<CryptographicException>();

			using (Assert.Multiple())
			{
				await Assert.That(runs).IsEqualTo(4);
				await Assert.That(p.Concat(q)).All(static word => word is 0);
			}
		}
	}

	// Bases are uniform in [2, w − 2] for the least w whose top two bits are set, where draws fall above w − 2 most often, at a length of a partial limb: neither a draw out of range nor the bits above the length reach a base.
	[Test]
	public async Task BasesAreUniformInRange()
	{
		const int Bits = 1028;
		const int Samples = 3000;
		int limbs = (Bits + 63) / 64;
		BigInteger w = BigInteger.One << Bits - 1 | BigInteger.One << Bits - 2 | 1;
		ulong[] wMinusOne = ToLimbs(w - 1, limbs);
		ulong[] b = new ulong[limbs];
		int[] tops = new int[4];
		int[] lows = new int[16];
		int outOfRange = 0;

		for (int i = 0; i < Samples; ++i)
		{
			SampleBase(b, wMinusOne, Bits);
			BigInteger value = ToBigInteger(b);
			outOfRange += value < 2 || value > w - 2 ? 1 : 0;
			++tops[(int)(value >> Bits - 2)];
			++lows[(int)(value & 15)];
		}

		// Below 3·2^(Bits − 2), the top two bits take three values alike; χ² bounds of 2 and 15 degrees of freedom that a uniform base exceeds with probability below 10^-6.
		double topChiSquare = tops.Take(3).Sum(static count => Math.Pow(count - Samples / 3.0, 2) / (Samples / 3.0));
		double lowChiSquare = lows.Sum(static count => Math.Pow(count - Samples / 16.0, 2) / (Samples / 16.0));

		using (Assert.Multiple())
		{
			await Assert.That(outOfRange).IsZero();
			await Assert.That(tops[3]).IsZero();
			await Assert.That(topChiSquare).IsLessThan(28);
			await Assert.That(lowChiSquare).IsLessThan(58);
		}
	}

	// A key takes little memory beyond that of the key itself, whatever the candidates it goes through: the contexts and buffers of the candidates last for the key.
	[Test]
	[NotInParallel]
	public async Task GenerateAllocatesLittlePerKey()
	{
		RsaPrivateOperation.Generate(2048, 65537).Dispose();
		long before = GC.GetAllocatedBytesForCurrentThread();
		RsaPrivateOperation.Generate(2048, 65537).Dispose();
		RsaPrivateOperation.Generate(2048, 65537).Dispose();
		long perKey = (GC.GetAllocatedBytesForCurrentThread() - before) / 2;

		await Assert.That(perKey).IsLessThan(64 * 1024);
	}

	private static BigInteger Hex(string value)
	{
		return FromBigEndian(Convert.FromHexString(value));
	}
}
