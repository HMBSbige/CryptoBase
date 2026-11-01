using System.Collections.ObjectModel;
using System.Diagnostics.CodeAnalysis;
using System.Numerics;

namespace CryptoBase.X509;

/// <summary>
/// Represents the result of validating the certificates that a peer presented: whether they are acceptable, every reason why not, and the certification path that the validator found.
/// </summary>
/// <remarks>
/// <para>
/// A result is valid exactly when <see cref="Errors" /> is empty. The default value is invalid, with the single error <see cref="CertificateValidationError.Unspecified" /> and no path, so a result that is never set rejects the certificates.
/// </para>
/// <para>
/// A validator that wraps another can accept what the other rejects, or reject what it accepts, by passing the parts of its result that it keeps to <see cref="Create" />; keeping <see cref="Path" /> and <see cref="PathEnd" /> lets the caller still inspect the path, such as the signature algorithm of each certificate that the path relies on.
/// </para>
/// <para>
/// Instances are immutable, so they may be used concurrently, and their collections are never <see langword="null" />.
/// </para>
/// </remarks>
public readonly struct CertificateValidationResult : IEquatable<CertificateValidationResult>
{
	// The order of Errors that Error documents, most important first.
	private static readonly CertificateValidationError[] Priority =
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

	private static readonly ReadOnlyCollection<CertificateValidationError> DefaultErrors = new([CertificateValidationError.Unspecified]);

	// Null only in the default value.
	private readonly ReadOnlyCollection<CertificateValidationError>? _errors;
	private readonly ReadOnlyCollection<Certificate>? _path;

	private CertificateValidationResult(ReadOnlyCollection<CertificateValidationError> errors, ReadOnlyCollection<Certificate> path, CertificatePathEnd pathEnd, string? message)
	{
		_errors = errors;
		_path = path;
		PathEnd = pathEnd;
		Message = message;
	}

	/// <summary>
	/// Gets a result that accepts the certificates, with no path.
	/// </summary>
	public static CertificateValidationResult Valid => new(ReadOnlyCollection<CertificateValidationError>.Empty, ReadOnlyCollection<Certificate>.Empty, CertificatePathEnd.None, null);

	/// <summary>
	/// Gets a value that indicates whether the certificates are acceptable, which is when <see cref="Errors" /> is empty.
	/// </summary>
	public bool IsValid => _errors is { Count: 0 };

	/// <summary>
	/// Gets the most important reason why the certificates are not acceptable, the first of <see cref="Errors" />, or <see cref="CertificateValidationError.Unspecified" /> if they are acceptable.
	/// </summary>
	/// <remarks>
	/// From the most important: <see cref="CertificateValidationError.Malformed" />, <see cref="CertificateValidationError.WeakAlgorithm" />, <see cref="CertificateValidationError.UnsupportedAlgorithm" />, <see cref="CertificateValidationError.InvalidSignature" />, <see cref="CertificateValidationError.Expired" />, <see cref="CertificateValidationError.Revoked" />, <see cref="CertificateValidationError.UntrustedRoot" />, <see cref="CertificateValidationError.NotValidForUsage" />, <see cref="CertificateValidationError.RevocationUnknown" />, <see cref="CertificateValidationError.Unspecified" /> and <see cref="CertificateValidationError.NameMismatch" />: what makes the path unacceptable comes before whom the certificate identifies.
	/// A result from <see cref="Invalid" /> has the error given there.
	/// </remarks>
	public CertificateValidationError Error => _errors is [var first, ..] ? first : CertificateValidationError.Unspecified;

	/// <summary>
	/// Gets every reason why the certificates are not acceptable, each once and most important first, in the order that <see cref="Error" /> describes; empty exactly when they are acceptable.
	/// </summary>
	public IReadOnlyList<CertificateValidationError> Errors => _errors ?? DefaultErrors;

	/// <summary>
	/// Gets a description of the problems for diagnostics, or <see langword="null" />.
	/// </summary>
	public string? Message { get; }

	/// <summary>
	/// Gets the certification path that the validator found, the peer's certificate first and then each issuer, up to a trust anchor or the last certificate that the validator found; empty if the validator reports no path.
	/// </summary>
	/// <remarks>A result that accepts the certificates may have a path that <see cref="PathEnd" /> reports as not ending at a trust anchor, when the validator's policy allows such a path.</remarks>
	public IReadOnlyList<Certificate> Path => _path ?? ReadOnlyCollection<Certificate>.Empty;

	/// <summary>
	/// Gets where <see cref="Path" /> ends: <see cref="CertificatePathEnd.None" /> exactly when it is empty.
	/// </summary>
	public CertificatePathEnd PathEnd { get; }

	/// <summary>
	/// Creates a result that rejects the certificates for one reason, with no path.
	/// </summary>
	/// <param name="error">Why the certificates are not acceptable.</param>
	/// <param name="message">A description of the problem for diagnostics, or <see langword="null" />.</param>
	/// <returns>The result, whose <see cref="Errors" /> holds <paramref name="error" /> alone.</returns>
	public static CertificateValidationResult Invalid(CertificateValidationError error, string? message = null)
	{
		return new CertificateValidationResult(new ReadOnlyCollection<CertificateValidationError>([error]), ReadOnlyCollection<Certificate>.Empty, CertificatePathEnd.None, message);
	}

	/// <summary>
	/// Creates a result from its errors and its path: one that accepts the certificates if <paramref name="errors" /> is empty, and rejects them otherwise.
	/// </summary>
	/// <remarks>The result holds each error once, ordered as <see cref="Error" /> describes, and holds a copy of the path.</remarks>
	/// <param name="errors">Why the certificates are not acceptable, in any order and with any repeats; empty if they are acceptable.</param>
	/// <param name="path">The certification path, the peer's certificate first; empty for none.</param>
	/// <param name="pathEnd">Where <paramref name="path" /> ends; <see cref="CertificatePathEnd.None" /> exactly when it is empty.</param>
	/// <param name="message">A description of the problems for diagnostics, or <see langword="null" />.</param>
	/// <returns>The result.</returns>
	/// <exception cref="ArgumentNullException"><paramref name="errors" /> or <paramref name="path" /> is <see langword="null" />.</exception>
	/// <exception cref="ArgumentOutOfRangeException"><paramref name="errors" /> holds a value that is not defined, or <paramref name="pathEnd" /> is not defined.</exception>
	/// <exception cref="ArgumentException"><paramref name="path" /> holds <see langword="null" />, or is empty when <paramref name="pathEnd" /> is not <see cref="CertificatePathEnd.None" /> or is not empty when it is.</exception>
	public static CertificateValidationResult Create(IEnumerable<CertificateValidationError> errors, IEnumerable<Certificate> path, CertificatePathEnd pathEnd, string? message = null)
	{
		ArgumentNullException.ThrowIfNull(errors);
		ArgumentNullException.ThrowIfNull(path);

		// A bit for each rank in Priority, which has fewer than 32 values.
		int present = 0;

		foreach (CertificateValidationError error in errors)
		{
			int rank = Array.IndexOf(Priority, error);

			if (rank < 0)
			{
				throw new ArgumentOutOfRangeException(nameof(errors), error, "The errors include a value that is not defined.");
			}

			present |= 1 << rank;
		}

		ReadOnlyCollection<CertificateValidationError> ordered = ReadOnlyCollection<CertificateValidationError>.Empty;

		if (present is not 0)
		{
			CertificateValidationError[] distinct = new CertificateValidationError[BitOperations.PopCount((uint)present)];
			int count = 0;

			for (int i = 0; i < Priority.Length; ++i)
			{
				if ((present >> i & 1) is not 0)
				{
					distinct[count++] = Priority[i];
				}
			}

			ordered = Array.AsReadOnly(distinct);
		}

		Certificate[] copy = [.. path];

		if (Array.IndexOf(copy, null) >= 0)
		{
			throw new ArgumentException("The path holds null.", nameof(path));
		}

		if (pathEnd is not (CertificatePathEnd.None or CertificatePathEnd.TrustAnchor or CertificatePathEnd.UntrustedRoot or CertificatePathEnd.MissingIssuer))
		{
			throw new ArgumentOutOfRangeException(nameof(pathEnd), pathEnd, "The path end is not defined.");
		}

		bool empty = copy.Length is 0;

		if (empty != pathEnd is CertificatePathEnd.None)
		{
			throw new ArgumentException("The path must be empty exactly when its end is None.", nameof(pathEnd));
		}

		return new CertificateValidationResult(ordered, empty ? ReadOnlyCollection<Certificate>.Empty : Array.AsReadOnly(copy), pathEnd, message);
	}

	/// <summary>
	/// Determines whether another result has the same errors, path, path end and message.
	/// </summary>
	/// <remarks>The paths must hold the same <see cref="Certificate" /> instances.</remarks>
	/// <param name="other">The result to compare with.</param>
	/// <returns><see langword="true" /> if <paramref name="other" /> is equal; otherwise, <see langword="false" />.</returns>
	public bool Equals(CertificateValidationResult other)
	{
		return PathEnd == other.PathEnd && Message == other.Message && Errors.SequenceEqual(other.Errors) && Path.SequenceEqual(other.Path);
	}

	/// <summary>
	/// Determines whether an object is a result with the same errors, path, path end and message.
	/// </summary>
	/// <remarks>The paths must hold the same <see cref="Certificate" /> instances.</remarks>
	/// <param name="obj">The object to compare with.</param>
	/// <returns><see langword="true" /> if <paramref name="obj" /> is an equal result; otherwise, <see langword="false" />.</returns>
	public override bool Equals([NotNullWhen(true)] object? obj)
	{
		return obj is CertificateValidationResult other && Equals(other);
	}

	/// <inheritdoc />
	public override int GetHashCode()
	{
		return HashCode.Combine(Error, Errors.Count, Path.Count, PathEnd, Message);
	}
}
