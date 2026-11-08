namespace CryptoBase.X509;

// The certificate policy processing of RFC 5280, Sec. 6.1, for one certification path, with the valid_policy_graph of RFC 9618, Sec. 5, in place of the valid_policy_tree: the two accept the same paths, and the graph has at most one node per policy at each depth, so its size is linear in the policies and mappings of the path.
// Nodes are kept by depth, and nodes without children are found at the end rather than pruned at each step (RFC 9618, Sec. 5.3, step (d)(3)), which changes nothing: every step reads only the nodes of the previous depth and the depth being built.
internal static class PolicyGraph
{
	public static readonly ReadOnlyMemory<byte> AnyPolicy = new byte[] { 0x55, 0x1D, 0x20, 0x00 };

	private static bool IsAnyPolicy(ReadOnlyMemory<byte> policy)
	{
		return policy.Span.SequenceEqual(AnyPolicy.Span);
	}

	// Checks a path, from the peer's certificate to the trust anchor at its end, which does not take part. Returns the problem of a path that no policy is valid for when one is required, or null.
	// The entries of the graph that the check handles, its policies, mappings and expected policies, count against budget; if they would exceed it, limitReached is set and the result is null.
	public static PathProblem? Check(List<PathNode> path, TrustAnchorCertificateValidator validator, ref long budget, out bool limitReached)
	{
		limitReached = false;
		int n = path.Count - 1;

		// Without a requirement for an explicit policy, explicit_policy stays above zero to the end of the path, so steps (f) of Sec. 6.1.3 and the wrap-up succeed, whatever the policies are.
		if (!validator.RequireExplicitPolicy && !HasRequireExplicitPolicy(path, n))
		{
			return null;
		}

		// RFC 5280, Sec. 6.1.2 (a), (d), (e) and (f).
		int explicitPolicy = validator.RequireExplicitPolicy ? 0 : n + 1;
		int policyMapping = validator.InhibitPolicyMapping ? 0 : n + 1;
		int inhibitAnyPolicy = validator.InhibitAnyPolicy ? 0 : n + 1;
		Dictionary<ReadOnlyMemory<byte>, Node>? level = new(ByteMemoryComparer.Instance) { [AnyPolicy] = new Node(AnyPolicy, [AnyPolicy], []) };

		for (int index = n - 1; index >= 0; --index)
		{
			PathNode node = path[index];
			DecodedExtensions extensions = node.Certificate.DecodedExtensions;
			bool last = index is 0;

			// Sec. 6.1.3 (d) and (e).
			if (level is not null)
			{
				if (extensions.CertificatePolicies.Value is { } policies)
				{
					if (!Spend(ref budget, policies.Policies.Length + 1 + CountExpected(level)))
					{
						limitReached = true;
						return null;
					}

					// (d)(2): anyPolicy counts where inhibit_anyPolicy allows it, or in a self-issued certificate that is not the last.
					level = NextDepth(level, policies, policies.HasAnyPolicy && (inhibitAnyPolicy > 0 || !last && node.SelfIssued));
				}
				else
				{
					level = null;
				}
			}

			// Sec. 6.1.3 (f).
			if (explicitPolicy is 0 && level is null)
			{
				return new PathProblem(CertificateValidationError.NotValidForUsage, "{0} leaves the path without a valid certificate policy, and the path requires an explicit policy.", node);
			}

			if (last)
			{
				break;
			}

			// Sec. 6.1.4 (b).
			if (level is not null && extensions.PolicyMappings.Value is { } mappings)
			{
				if (!Spend(ref budget, mappings.Mappings.Length))
				{
					limitReached = true;
					return null;
				}

				level = ApplyMappings(level, mappings, policyMapping > 0);
			}

			// Sec. 6.1.4 (h).
			if (!node.SelfIssued)
			{
				explicitPolicy = Math.Max(0, explicitPolicy - 1);
				policyMapping = Math.Max(0, policyMapping - 1);
				inhibitAnyPolicy = Math.Max(0, inhibitAnyPolicy - 1);
			}

			// Sec. 6.1.4 (i) and (j).
			if (extensions.PolicyConstraints.Value is { } constraints)
			{
				explicitPolicy = Math.Min(explicitPolicy, constraints.RequireExplicitPolicy ?? int.MaxValue);
				policyMapping = Math.Min(policyMapping, constraints.InhibitPolicyMapping ?? int.MaxValue);
			}

			inhibitAnyPolicy = Math.Min(inhibitAnyPolicy, extensions.InhibitAnyPolicy.Value ?? int.MaxValue);
		}

		// Sec. 6.1.5 (a) and (b).
		PathNode leaf = path[0];

		if (explicitPolicy is not 0)
		{
			--explicitPolicy;
		}

		if (leaf.Certificate.DecodedExtensions.PolicyConstraints.Value is { RequireExplicitPolicy: 0 })
		{
			explicitPolicy = 0;
		}

		if (explicitPolicy > 0 || level is not null && HasAcceptablePolicy(level, validator.InitialPolicySet))
		{
			return null;
		}

		return new PathProblem(CertificateValidationError.NotValidForUsage, "No certificate policy of the path is acceptable to the validator, and the path requires an explicit policy.");
	}

	private static bool Spend(ref long budget, long work)
	{
		if (work > budget)
		{
			return false;
		}

		budget -= work;
		return true;
	}

	private static bool HasRequireExplicitPolicy(List<PathNode> path, int n)
	{
		for (int i = 0; i < n; ++i)
		{
			if (path[i].Certificate.DecodedExtensions.PolicyConstraints.Value is { RequireExplicitPolicy: not null })
			{
				return true;
			}
		}

		return false;
	}

	private static long CountExpected(Dictionary<ReadOnlyMemory<byte>, Node> level)
	{
		long count = 0;

		foreach (Node node in level.Values)
		{
			count += node.Expected.Length;
		}

		return count;
	}

	// RFC 9618, Sec. 5.3, step (d): the nodes of the next depth, or null if there are none. anyPolicy says whether the policy processes as such.
	private static Dictionary<ReadOnlyMemory<byte>, Node>? NextDepth(Dictionary<ReadOnlyMemory<byte>, Node> level, CertificatePolicies policies, bool anyPolicy)
	{
		// The nodes of this depth that expect each policy.
		Dictionary<ReadOnlyMemory<byte>, List<Node>> expected = new(ByteMemoryComparer.Instance);

		foreach (Node node in level.Values)
		{
			foreach (ReadOnlyMemory<byte> policy in node.Expected)
			{
				if (!expected.TryGetValue(policy, out List<Node>? parents))
				{
					parents = [];
					expected.Add(policy, parents);
				}

				parents.Add(node);
			}
		}

		level.TryGetValue(AnyPolicy, out Node? anyNode);
		Dictionary<ReadOnlyMemory<byte>, Node> next = new(ByteMemoryComparer.Instance);

		foreach (ReadOnlyMemory<byte> policy in policies.Policies)
		{
			// (d)(1)(i).
			if (expected.TryGetValue(policy, out List<Node>? parents))
			{
				next.Add(policy, new Node(policy, [policy], parents));
			}
			else if (anyNode is not null)
			{
				// (d)(1)(ii).
				next.Add(policy, new Node(policy, [policy], [anyNode]));
			}
		}

		if (anyPolicy)
		{
			// (d)(2).
			foreach ((ReadOnlyMemory<byte> policy, List<Node> parents) in expected)
			{
				if (!next.ContainsKey(policy))
				{
					next.Add(policy, new Node(policy, [policy], parents));
				}
			}
		}

		return next.Count > 0 ? next : null;
	}

	// RFC 9618, Sec. 5.4, step (b), for the nodes of the depth of a certificate with policy mappings: returns the depth, or null if no node is left.
	private static Dictionary<ReadOnlyMemory<byte>, Node>? ApplyMappings(Dictionary<ReadOnlyMemory<byte>, Node> level, PolicyMappings mappings, bool mappingAllowed)
	{
		Dictionary<ReadOnlyMemory<byte>, List<ReadOnlyMemory<byte>>> byIssuerPolicy = new(ByteMemoryComparer.Instance);

		foreach ((ReadOnlyMemory<byte> issuerDomainPolicy, ReadOnlyMemory<byte> subjectDomainPolicy) in mappings.Mappings)
		{
			if (!byIssuerPolicy.TryGetValue(issuerDomainPolicy, out List<ReadOnlyMemory<byte>>? subjects))
			{
				subjects = [];
				byIssuerPolicy.Add(issuerDomainPolicy, subjects);
			}

			subjects.Add(subjectDomainPolicy);
		}

		level.TryGetValue(AnyPolicy, out Node? anyNode);

		foreach ((ReadOnlyMemory<byte> issuerDomainPolicy, List<ReadOnlyMemory<byte>> subjects) in byIssuerPolicy)
		{
			if (!mappingAllowed)
			{
				// (b)(3)(i); the pruning of (b)(3)(ii) happens at the end.
				level.Remove(issuerDomainPolicy);
			}
			else if (level.TryGetValue(issuerDomainPolicy, out Node? node))
			{
				// (b)(1).
				node.Expected = [.. subjects];
			}
			else if (anyNode is not null)
			{
				// (b)(2); anyPolicy at a depth above zero has the anyPolicy of the previous depth for its one parent.
				level.Add(issuerDomainPolicy, new Node(issuerDomainPolicy, [.. subjects], [anyNode.Parents[0]]));
			}
		}

		return level.Count > 0 ? level : null;
	}

	// RFC 9618, Sec. 5.5, step (g): whether the user-constrained policy set is not empty, the set being every policy if initial is null. Every node that leads to one of the last depth counts; the others are those that pruning removes.
	private static bool HasAcceptablePolicy(Dictionary<ReadOnlyMemory<byte>, Node> level, HashSet<ReadOnlyMemory<byte>>? initial)
	{
		if (initial is null || level.ContainsKey(AnyPolicy))
		{
			return true;
		}

		List<Node> live = [.. level.Values];

		foreach (Node node in live)
		{
			node.Live = true;
		}

		for (int i = 0; i < live.Count; ++i)
		{
			Node node = live[i];

			// valid_policy_node_set: a policy other than anyPolicy with anyPolicy for its one parent.
			if (node.Parents is [var only] && IsAnyPolicy(only.Policy) && !IsAnyPolicy(node.Policy) && initial.Contains(node.Policy))
			{
				return true;
			}

			foreach (Node parent in node.Parents)
			{
				if (!parent.Live)
				{
					parent.Live = true;
					live.Add(parent);
				}
			}
		}

		return false;
	}

	// A node of the valid_policy_graph, without the qualifier_set, which the validator does not return. Parents are the nodes of the previous depth; expected_policy_set is Expected, which step (b)(1) replaces.
	private sealed class Node(ReadOnlyMemory<byte> policy, ReadOnlyMemory<byte>[] expected, List<Node> parents)
	{
		public ReadOnlyMemory<byte> Policy { get; } = policy;

		public ReadOnlyMemory<byte>[] Expected { get; set; } = expected;

		public List<Node> Parents { get; } = parents;

		public bool Live { get; set; }
	}
}
