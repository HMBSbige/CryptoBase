using CryptoBase.X509;
using static CryptoBase.Tests.X509.X509TestUtils;

namespace CryptoBase.Tests.X509;

public class CertificateValidationResultTest
{
	// The order that the documentation of Error gives, from the most important.
	private static readonly CertificateValidationError[] DocumentedOrder =
	[
		CertificateValidationError.Malformed,
		CertificateValidationError.WeakAlgorithm,
		CertificateValidationError.UnsupportedAlgorithm,
		CertificateValidationError.InvalidSignature,
		CertificateValidationError.Expired,
		CertificateValidationError.Revoked,
		CertificateValidationError.UntrustedRoot,
		CertificateValidationError.NotValidForUsage,
		CertificateValidationError.RevocationUnknown,
		CertificateValidationError.Unspecified,
		CertificateValidationError.NameMismatch,
	];

	[Test]
	public async Task TheDefaultRejectsWithoutAPath()
	{
		CertificateValidationResult result = default;

		using (Assert.Multiple())
		{
			await Assert.That(result.IsValid).IsFalse();
			await Assert.That(result.Error).IsEqualTo(CertificateValidationError.Unspecified);
			await Assert.That(result.Errors).IsEquivalentTo([CertificateValidationError.Unspecified], CollectionOrdering.Matching);
			await Assert.That(result.Path).IsNotNull().And.IsEmpty();
			await Assert.That(result.PathEnd).IsEqualTo(CertificatePathEnd.None);
			await Assert.That(result.Message).IsNull();
		}
	}

	[Test]
	public async Task ValidAndInvalidKeepTheirMeaning()
	{
		CertificateValidationResult valid = CertificateValidationResult.Valid;
		CertificateValidationResult invalid = CertificateValidationResult.Invalid(CertificateValidationError.Revoked, "message");
		CertificateValidationResult undefined = CertificateValidationResult.Invalid((CertificateValidationError)99);

		using (Assert.Multiple())
		{
			await Assert.That(valid.IsValid).IsTrue();
			await Assert.That(valid.Error).IsEqualTo(CertificateValidationError.Unspecified);
			await Assert.That(valid.Errors).IsEmpty();
			await Assert.That(valid.Path).IsEmpty();
			await Assert.That(valid.PathEnd).IsEqualTo(CertificatePathEnd.None);

			await Assert.That(invalid.IsValid).IsFalse();
			await Assert.That(invalid.Error).IsEqualTo(CertificateValidationError.Revoked);
			await Assert.That(invalid.Errors).IsEquivalentTo([CertificateValidationError.Revoked], CollectionOrdering.Matching);
			await Assert.That(invalid.Message).IsEqualTo("message");
			await Assert.That(invalid.Path).IsEmpty();

			// Invalid takes any value, as it did before Errors.
			await Assert.That(undefined.Error).IsEqualTo((CertificateValidationError)99);
			await Assert.That(undefined.IsValid).IsFalse();
		}
	}

	[Test]
	public async Task CreateOrdersTheErrorsByImportance()
	{
		CertificateValidationError[] shuffled = [.. DocumentedOrder.Reverse(), CertificateValidationError.Expired, CertificateValidationError.Malformed];

		CertificateValidationResult all = CertificateValidationResult.Create(shuffled, [], CertificatePathEnd.None, "message");
		CertificateValidationResult some = CertificateValidationResult.Create([CertificateValidationError.NameMismatch, CertificateValidationError.Unspecified, CertificateValidationError.UntrustedRoot, CertificateValidationError.Expired], [], CertificatePathEnd.None);

		using (Assert.Multiple())
		{
			await Assert.That(all.Errors).IsEquivalentTo(DocumentedOrder, CollectionOrdering.Matching);
			await Assert.That(all.Error).IsEqualTo(CertificateValidationError.Malformed);
			await Assert.That(all.Message).IsEqualTo("message");
			await Assert.That(some.Errors).IsEquivalentTo([CertificateValidationError.Expired, CertificateValidationError.UntrustedRoot, CertificateValidationError.Unspecified, CertificateValidationError.NameMismatch], CollectionOrdering.Matching);
			await Assert.That(some.Error).IsEqualTo(CertificateValidationError.Expired);
		}
	}

	[Test]
	public async Task TheOrderHasEveryError()
	{
		CertificateValidationError[] defined = Enum.GetValues<CertificateValidationError>();

		CertificateValidationResult all = CertificateValidationResult.Create(defined, [], CertificatePathEnd.None);

		using (Assert.Multiple())
		{
			await Assert.That(DocumentedOrder).IsEquivalentTo(defined);
			await Assert.That(all.Errors).IsEquivalentTo(DocumentedOrder, CollectionOrdering.Matching);
		}
	}

	[Test]
	public async Task AWrapperCanAcceptAndKeepThePath()
	{
		Certificate leaf = SelfSignedP256();
		Certificate issuer = SelfSignedP256();
		CertificateValidationResult rejected = CertificateValidationResult.Create([CertificateValidationError.UntrustedRoot, CertificateValidationError.Expired], [leaf, issuer], CertificatePathEnd.MissingIssuer, "partial");

		CertificateValidationResult allowed = CertificateValidationResult.Create(rejected.Errors.Where(static error => error is not (CertificateValidationError.UntrustedRoot or CertificateValidationError.Expired)), rejected.Path, rejected.PathEnd, rejected.Message);
		CertificateValidationResult stillRejected = CertificateValidationResult.Create(rejected.Errors.Where(static error => error is not CertificateValidationError.UntrustedRoot), rejected.Path, rejected.PathEnd);

		using (Assert.Multiple())
		{
			await Assert.That(allowed.IsValid).IsTrue();
			await Assert.That(allowed.Errors).IsEmpty();
			await Assert.That(allowed.Path).IsEquivalentTo([leaf, issuer], CollectionOrdering.Matching);
			await Assert.That(allowed.Path[0]).IsSameReferenceAs(leaf);
			await Assert.That(allowed.PathEnd).IsEqualTo(CertificatePathEnd.MissingIssuer);
			await Assert.That(allowed.Message).IsEqualTo("partial");
			await Assert.That(stillRejected.Errors).IsEquivalentTo([CertificateValidationError.Expired], CollectionOrdering.Matching);
			await Assert.That(stillRejected.PathEnd).IsEqualTo(CertificatePathEnd.MissingIssuer);
		}
	}

	[Test]
	public async Task TheDocumentedWrapperAcceptsAnUntrustedRootAndNotAPartialChain()
	{
		Certificate leaf = SelfSignedP256();
		Certificate root = SelfSignedP256();
		CertificateValidationContext context = new([leaf], CertificateUsage.ServerAuthentication);

		CertificateValidationResult untrusted = await new AnyRootValidator(new FixedValidator(CertificateValidationResult.Create([CertificateValidationError.UntrustedRoot], [leaf, root], CertificatePathEnd.UntrustedRoot))).ValidateAsync(context);
		CertificateValidationResult expired = await new AnyRootValidator(new FixedValidator(CertificateValidationResult.Create([CertificateValidationError.UntrustedRoot, CertificateValidationError.Expired], [leaf, root], CertificatePathEnd.UntrustedRoot))).ValidateAsync(context);
		CertificateValidationResult partial = await new AnyRootValidator(new FixedValidator(CertificateValidationResult.Create([CertificateValidationError.UntrustedRoot], [leaf], CertificatePathEnd.MissingIssuer))).ValidateAsync(context);

		using (Assert.Multiple())
		{
			await Assert.That(untrusted.IsValid).IsTrue();
			await Assert.That(untrusted.Path).IsEquivalentTo([leaf, root], CollectionOrdering.Matching);
			await Assert.That(untrusted.PathEnd).IsEqualTo(CertificatePathEnd.UntrustedRoot);
			await Assert.That(expired.Errors).IsEquivalentTo([CertificateValidationError.Expired], CollectionOrdering.Matching);
			await Assert.That(partial.Errors).IsEquivalentTo([CertificateValidationError.UntrustedRoot], CollectionOrdering.Matching);
			await Assert.That(partial.PathEnd).IsEqualTo(CertificatePathEnd.MissingIssuer);
		}
	}

	[Test]
	public async Task CreateCopiesItsInputsAndExposesThemReadOnly()
	{
		Certificate first = SelfSignedP256();
		Certificate second = SelfSignedP256();
		CertificateValidationError[] errors = [CertificateValidationError.Revoked];
		Certificate[] path = [first];

		CertificateValidationResult result = CertificateValidationResult.Create(errors, path, CertificatePathEnd.TrustAnchor);
		errors[0] = CertificateValidationError.Expired;
		path[0] = second;

		using (Assert.Multiple())
		{
			await Assert.That(result.Errors).IsEquivalentTo([CertificateValidationError.Revoked], CollectionOrdering.Matching);
			await Assert.That(result.Path[0]).IsSameReferenceAs(first);
			await Assert.That(result.Errors is ICollection<CertificateValidationError> { IsReadOnly: true }).IsTrue();
			await Assert.That(result.Path is ICollection<Certificate> { IsReadOnly: true }).IsTrue();
		}
	}

	// Results compare by value, as they did before they held collections.
	[Test]
	public async Task ResultsWithTheSameContentsAreEqual()
	{
		Certificate certificate = SelfSignedP256();
		CertificateValidationResult withPath = CertificateValidationResult.Create([CertificateValidationError.Expired], [certificate], CertificatePathEnd.TrustAnchor, "message");

		using (Assert.Multiple())
		{
			await Assert.That(CertificateValidationResult.Invalid(CertificateValidationError.Revoked, "message")).IsEqualTo(CertificateValidationResult.Invalid(CertificateValidationError.Revoked, "message"));
			await Assert.That(CertificateValidationResult.Invalid(CertificateValidationError.Revoked).GetHashCode()).IsEqualTo(CertificateValidationResult.Invalid(CertificateValidationError.Revoked).GetHashCode());
			await Assert.That(CertificateValidationResult.Valid).IsEqualTo(CertificateValidationResult.Create([], [], CertificatePathEnd.None));
			await Assert.That(default(CertificateValidationResult)).IsEqualTo(CertificateValidationResult.Invalid(CertificateValidationError.Unspecified));
			await Assert.That(withPath).IsEqualTo(CertificateValidationResult.Create([CertificateValidationError.Expired, CertificateValidationError.Expired], [certificate], CertificatePathEnd.TrustAnchor, "message"));
			await Assert.That(withPath).IsNotEqualTo(CertificateValidationResult.Create([CertificateValidationError.Expired], [certificate], CertificatePathEnd.TrustAnchor, "other"));
			await Assert.That(withPath).IsNotEqualTo(CertificateValidationResult.Create([CertificateValidationError.Expired], [SelfSignedP256()], CertificatePathEnd.TrustAnchor, "message"));
			await Assert.That(withPath).IsNotEqualTo(CertificateValidationResult.Create([CertificateValidationError.Revoked], [certificate], CertificatePathEnd.TrustAnchor, "message"));
			await Assert.That(CertificateValidationResult.Valid.Equals(null)).IsFalse();
		}
	}

	[Test]
	public async Task CreateChecksItsArguments()
	{
		Certificate certificate = SelfSignedP256();

		using (Assert.Multiple())
		{
			await Assert.That(() => CertificateValidationResult.Create(null!, [], CertificatePathEnd.None)).ThrowsExactly<ArgumentNullException>().WithParameterName("errors");
			await Assert.That(() => CertificateValidationResult.Create([], null!, CertificatePathEnd.None)).ThrowsExactly<ArgumentNullException>().WithParameterName("path");
			await Assert.That(() => CertificateValidationResult.Create([(CertificateValidationError)99], [], CertificatePathEnd.None)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("errors");
			await Assert.That(() => CertificateValidationResult.Create([], [certificate], (CertificatePathEnd)4)).ThrowsExactly<ArgumentOutOfRangeException>().WithParameterName("pathEnd");
			await Assert.That(() => CertificateValidationResult.Create([], [certificate, null!], CertificatePathEnd.TrustAnchor)).ThrowsExactly<ArgumentException>().WithParameterName("path");
			await Assert.That(() => CertificateValidationResult.Create([], [], CertificatePathEnd.TrustAnchor)).ThrowsExactly<ArgumentException>().WithParameterName("pathEnd");
			await Assert.That(() => CertificateValidationResult.Create([], [certificate], CertificatePathEnd.None)).ThrowsExactly<ArgumentException>().WithParameterName("pathEnd");
		}
	}

	// The validator of the example in docs/x509.md.
	private sealed class AnyRootValidator(ICertificateValidator inner) : ICertificateValidator
	{
		public async ValueTask<CertificateValidationResult> ValidateAsync(CertificateValidationContext context, CancellationToken cancellationToken = default)
		{
			CertificateValidationResult result = await inner.ValidateAsync(context, cancellationToken);

			// UntrustedRoot also stands for a partial chain, which ends at MissingIssuer, and stays an error then.
			if (result.PathEnd is not CertificatePathEnd.UntrustedRoot)
			{
				return result;
			}

			return CertificateValidationResult.Create(result.Errors.Where(static error => error is not CertificateValidationError.UntrustedRoot), result.Path, result.PathEnd, result.Message);
		}
	}

	private sealed class FixedValidator(CertificateValidationResult result) : ICertificateValidator
	{
		public ValueTask<CertificateValidationResult> ValidateAsync(CertificateValidationContext context, CancellationToken cancellationToken = default)
		{
			return ValueTask.FromResult(result);
		}
	}
}
