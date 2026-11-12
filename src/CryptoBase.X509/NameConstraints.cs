using System.Buffers;
using System.Text;

namespace CryptoBase.X509;

// The value of a name constraints extension (RFC 5280, Sec. 4.2.1.10), for certification path validation: the subtrees of the forms that are matched, dNSName, iPAddress, rfc822Name and directoryName, and which other forms the subtrees name.
// Decoding checks every subtree: its base must be a GeneralName whose form is valid, its minimum and maximum absent as the profile requires, and at least one of the two lists present, neither empty. The values are slices of the extension's memory, and the instance is immutable.
internal sealed class NameConstraints
{
	private static readonly Asn1Tag PermittedSubtreesTag = new(TagClass.ContextSpecific, 0, true);
	private static readonly Asn1Tag ExcludedSubtreesTag = new(TagClass.ContextSpecific, 1, true);

	private NameConstraints(NameSubtrees permitted, NameSubtrees excluded)
	{
		Permitted = permitted;
		Excluded = excluded;
	}

	public NameSubtrees Permitted { get; }

	public NameSubtrees Excluded { get; }

	// The comparisons that Check makes at most for the names. A directoryName and a subtree can compare every attribute of one with every attribute of the other, within a relative name of equal size, so the product of their costs bounds them, without walking them here.
	public long CountComparisons(ConstrainedNames names)
	{
		long subtrees = (long)names.DnsNames.Length * (Permitted.DnsNames.Length + Excluded.DnsNames.Length);
		subtrees += (long)names.IPAddresses.Length * (Permitted.IPAddresses.Length + Excluded.IPAddresses.Length);
		subtrees += (long)names.Mailboxes.Length * (Permitted.Mailboxes.Length + Excluded.Mailboxes.Length);

		if (Permitted.DirectoryNames.Length + Excluded.DirectoryNames.Length is 0)
		{
			return subtrees;
		}

		long nameWork = 0;

		foreach (DistinguishedName name in names.DirectoryNames)
		{
			nameWork += name.Work;
		}

		return subtrees + nameWork * (Permitted.DirectoryNameWork + Excluded.DirectoryNameWork);
	}

	// Whether the names are within the constraints (RFC 5280, Sec. 6.1.3 (b) and (c)): each name of a matched form must be within a permitted subtree of its form, if there is one, and within no excluded subtree; a name of another form that a subtree also names cannot be checked.
	// Returns the reason why not, or null; text is the description for the reason's message.
	public CertificateValidationError? Check(ConstrainedNames names, out string? text)
	{
		// A name of a matched form must be valid only if a subtree of its form applies.
		bool dnsNames = Permitted.DnsNames.Length + Excluded.DnsNames.Length > 0;
		bool mailboxes = Permitted.Mailboxes.Length + Excluded.Mailboxes.Length > 0;

		foreach (DnsNamePattern name in dnsNames ? names.DnsNames : [])
		{
			if (!name.IsValid)
			{
				text = $"has the DNS name \"{PathProblem.Escape(name.Value)}\", which is not a valid DNS name to check against the name constraints of {{1}}";
				return CertificateValidationError.Malformed;
			}

			if (Permitted.DnsNames.Length > 0 && !Permitted.Permits(name))
			{
				text = $"has the DNS name \"{name.Value}\", which the name constraints of {{1}} do not permit";
				return CertificateValidationError.NotValidForUsage;
			}

			if (Excluded.Excludes(name))
			{
				text = $"has the DNS name \"{name.Value}\", which the name constraints of {{1}} exclude";
				return CertificateValidationError.NotValidForUsage;
			}
		}

		foreach (ReadOnlyMemory<byte> address in names.IPAddresses)
		{
			bool permitted = Permitted.IPAddresses.Length is 0 || NameSubtrees.ContainsAddress(Permitted.IPAddresses, address.Span);

			if (!permitted || NameSubtrees.ContainsAddress(Excluded.IPAddresses, address.Span))
			{
				text = $"has the IP address {new System.Net.IPAddress(address.Span)}, which the name constraints of {{1}} {(permitted ? "exclude" : "do not permit")}";
				return CertificateValidationError.NotValidForUsage;
			}
		}

		foreach (Mailbox? mailbox in mailboxes ? names.Mailboxes : [])
		{
			if (mailbox is not { } valid)
			{
				text = "has an email address that is not a valid mailbox to check against the name constraints of {1}";
				return CertificateValidationError.Malformed;
			}

			bool permitted = Permitted.Mailboxes.Length is 0 || NameSubtrees.ContainsMailbox(Permitted.Mailboxes, valid);

			if (!permitted || NameSubtrees.ContainsMailbox(Excluded.Mailboxes, valid))
			{
				text = $"has the email address \"{PathProblem.Escape(valid.LocalPart)}@{valid.Domain}\", which the name constraints of {{1}} {(permitted ? "exclude" : "do not permit")}";
				return CertificateValidationError.NotValidForUsage;
			}
		}

		foreach (DistinguishedName name in Permitted.DirectoryNames.Length + Excluded.DirectoryNames.Length > 0 ? names.DirectoryNames : [])
		{
			if (Permitted.DirectoryNames.Length > 0 && !NameSubtrees.ContainsDirectoryName(Permitted.DirectoryNames, name))
			{
				text = $"has the directory name \"{name.Describe()}\", which the name constraints of {{1}} do not permit";
				return CertificateValidationError.NotValidForUsage;
			}

			// RFC 5280, Sec. 7.1, compares by all of RFC 4518: a name that a complete comparison could find within an excluded subtree must not escape it, nor one whose domainComponent, emailAddress or unstructuredName differs only in what RFC 4518 removes, by which LDAP compares the first (RFC 4519) and a relying party with caseIgnoreMatch alone the others, while one that a permitted subtree misses is only left outside it.
			if (NameSubtrees.MightContainDirectoryName(Excluded.DirectoryNames, name, out bool certain))
			{
				text = certain
					? $"has the directory name \"{name.Describe()}\", which the name constraints of {{1}} exclude"
					: $"has the directory name \"{name.Describe()}\", which might be within a subtree that the name constraints of {{1}} exclude: it cannot be compared exactly, or differs from the subtree only in characters that the preparation of RFC 4518 ignores";
				return CertificateValidationError.NotValidForUsage;
			}
		}

		// The other forms are not matched: a certificate with a name of one that a subtree names fails, as RFC 5280 asks to process it or reject the certificate (Sec. 4.2.1.10).
		foreach (GeneralNameType form in (ReadOnlySpan<GeneralNameType>)[GeneralNameType.OtherName, GeneralNameType.X400Address, GeneralNameType.EdiPartyName, GeneralNameType.UniformResourceIdentifier, GeneralNameType.RegisteredId])
		{
			if (names.HasForm(form) && (Permitted.HasForm(form) || Excluded.HasForm(form)))
			{
				text = $"has a name of the form {form}, which the name constraints of {{1}} constrain and the validator does not match";
				return CertificateValidationError.NotValidForUsage;
			}
		}

		text = null;
		return null;
	}

	// NameConstraints ::= SEQUENCE { permittedSubtrees [0] GeneralSubtrees OPTIONAL, excludedSubtrees [1] GeneralSubtrees OPTIONAL }, with implicit tags; RFC 5280 requires one of them.
	public static NameConstraints Read(ReadOnlyMemory<byte> value)
	{
		DerReader sequence = DerReader.ReadSoleSequence(value);
		NameSubtrees? permitted = sequence.PeekTagIs(PermittedSubtreesTag) ? NameSubtrees.Read(ref sequence, PermittedSubtreesTag) : null;
		NameSubtrees? excluded = sequence.PeekTagIs(ExcludedSubtreesTag) ? NameSubtrees.Read(ref sequence, ExcludedSubtreesTag) : null;
		sequence.ThrowIfNotEmpty();

		if (permitted is null && excluded is null)
		{
			throw new AsnContentException("The name constraints have neither permitted nor excluded subtrees.");
		}

		return new NameConstraints(permitted ?? NameSubtrees.Empty, excluded ?? NameSubtrees.Empty);
	}
}

// The subtrees of one list of a name constraints extension.
internal sealed class NameSubtrees
{
	public static readonly NameSubtrees Empty = new([], [], [], [], 0);

	private readonly int _forms;

	private NameSubtrees(string[] dnsNames, ReadOnlyMemory<byte>[] addresses, MailboxConstraint[] mailboxes, DistinguishedName[] directoryNames, int forms)
	{
		DnsNames = dnsNames;
		IPAddresses = addresses;
		Mailboxes = mailboxes;
		DirectoryNames = directoryNames;
		_forms = forms;

		foreach (DistinguishedName directoryName in directoryNames)
		{
			DirectoryNameWork += directoryName.Work;
		}
	}

	// The dNSName subtrees: DNS names, or empty for every name.
	public string[] DnsNames { get; }

	// The iPAddress subtrees: an IPv4 address and its mask in 8 octets, or an IPv6 address and its mask in 32, the mask a prefix of ones.
	public ReadOnlyMemory<byte>[] IPAddresses { get; }

	public MailboxConstraint[] Mailboxes { get; }

	public DistinguishedName[] DirectoryNames { get; }

	public long DirectoryNameWork { get; }

	public bool HasForm(GeneralNameType form)
	{
		return (_forms & 1 << (int)form) is not 0;
	}

	// RFC 5280, Sec. 4.2.1.10: a DNS name is within a subtree if it is the subtree's name with zero or more labels added on the left; every name is within the empty subtree. A wildcard stands for every name of one label more than its base, all of which must be within one subtree.
	public bool Permits(DnsNamePattern name)
	{
		foreach (string subtree in DnsNames)
		{
			if (IsWithin(name.Base, subtree))
			{
				return true;
			}
		}

		return false;
	}

	// A wildcard is excluded if a name that it stands for is: its base is within the subtree, or the subtree is its base with one label added.
	public bool Excludes(DnsNamePattern name)
	{
		foreach (string subtree in DnsNames)
		{
			if (IsWithin(name.Base, subtree) || name.IsWildcard && subtree.Length > name.Base.Length + 1 && IsWithin(subtree, name.Base) && subtree.AsSpan(0, subtree.Length - name.Base.Length - 1).IndexOf('.') < 0)
			{
				return true;
			}
		}

		return false;
	}

	public static bool ContainsAddress(ReadOnlyMemory<byte>[] subtrees, ReadOnlySpan<byte> address)
	{
		foreach (ReadOnlyMemory<byte> subtree in subtrees)
		{
			ReadOnlySpan<byte> network = subtree.Span;

			if (network.Length != 2 * address.Length)
			{
				continue;
			}

			// The prefix and the mask are sliced to the length of the address, so that the loop indexes all three without bounds checks.
			ReadOnlySpan<byte> prefix = network.Slice(0, address.Length);
			ReadOnlySpan<byte> mask = network.Slice(address.Length, address.Length);
			int i = 0;

			while (i < address.Length && ((address[i] ^ prefix[i]) & mask[i]) is 0)
			{
				++i;
			}

			if (i == address.Length)
			{
				return true;
			}
		}

		return false;
	}

	public static bool ContainsMailbox(MailboxConstraint[] subtrees, Mailbox mailbox)
	{
		foreach (MailboxConstraint subtree in subtrees)
		{
			if (subtree.Permits(mailbox))
			{
				return true;
			}
		}

		return false;
	}

	public static bool ContainsDirectoryName(DistinguishedName[] subtrees, DistinguishedName name)
	{
		foreach (DistinguishedName subtree in subtrees)
		{
			if (name.IsWithin(subtree))
			{
				return true;
			}
		}

		return false;
	}

	// Whether a subtree may hold the name, as DistinguishedName.MightBeWithin decides; certain tells whether one does, as IsWithin decides, which only a name that may be within one needs.
	public static bool MightContainDirectoryName(DistinguishedName[] subtrees, DistinguishedName name, out bool certain)
	{
		bool might = false;

		foreach (DistinguishedName subtree in subtrees)
		{
			if (!name.MightBeWithin(subtree))
			{
				continue;
			}

			might = true;

			if (name.IsWithin(subtree))
			{
				certain = true;
				return true;
			}
		}

		certain = false;
		return might;
	}

	// GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree, implicitly tagged.
	public static NameSubtrees Read(ref DerReader reader, Asn1Tag tag)
	{
		DerReader subtrees = reader.ReadSequence(tag);
		subtrees.ThrowIfEmpty();
		List<string> dnsNames = [];
		List<ReadOnlyMemory<byte>> addresses = [];
		List<MailboxConstraint> mailboxes = [];
		List<DistinguishedName> directoryNames = [];
		int forms = 0;

		while (subtrees.HasData)
		{
			// GeneralSubtree ::= SEQUENCE { base GeneralName, minimum [0] BaseDistance DEFAULT 0, maximum [1] BaseDistance OPTIONAL }. The profile requires a minimum of zero, which DER leaves out, and no maximum.
			DerReader subtree = subtrees.ReadSequence();
			GeneralName name = GeneralName.Read(ref subtree);
			subtree.ThrowIfNotEmpty();
			forms |= 1 << (int)name.Type;

			switch (name.Type)
			{
				case GeneralNameType.DnsName:
				{
					string value = Encoding.ASCII.GetString(name.Value.Span);

					// A DNS name, or empty for every name; a wildcard or a leading period, as URI subtrees allow, is not one (Sec. 4.2.1.10).
					if (value.Length > 0 && !HostName.IsDnsName(value))
					{
						throw new AsnContentException("A dNSName subtree is not a DNS name.");
					}

					dnsNames.Add(value);
					break;
				}
				case GeneralNameType.IPAddress:
				{
					if (!IsAddressRange(name.Value.Span))
					{
						throw new AsnContentException("An iPAddress subtree is not an address and the mask of a prefix.");
					}

					addresses.Add(name.Value);
					break;
				}
				case GeneralNameType.Rfc822Name:
				{
					mailboxes.Add(MailboxConstraint.Parse(Encoding.ASCII.GetString(name.Value.Span)) ?? throw new AsnContentException("An rfc822Name subtree is neither a mailbox, a host nor a domain."));
					break;
				}
				case GeneralNameType.DirectoryName:
				{
					directoryNames.Add(DistinguishedName.Read(name.Value));
					break;
				}
			}
		}

		return new NameSubtrees([.. dnsNames], [.. addresses], [.. mailboxes], [.. directoryNames], forms);
	}

	// Whether a DNS name is within a subtree, ignoring the case of ASCII letters. Both are valid, or the subtree empty.
	public static bool IsWithin(ReadOnlySpan<char> name, ReadOnlySpan<char> subtree)
	{
		if (subtree.IsEmpty)
		{
			return true;
		}

		if (name.Length == subtree.Length)
		{
			return Ascii.EqualsIgnoreCase(name, subtree);
		}

		return name.Length > subtree.Length && name[name.Length - subtree.Length - 1] is '.' && Ascii.EqualsIgnoreCase(name.Slice(name.Length - subtree.Length), subtree);
	}

	// Eight or 32 octets, an address and a mask whose ones come first, in the style of CIDR (RFC 4632) that Sec. 4.2.1.10 requires.
	private static bool IsAddressRange(ReadOnlySpan<byte> value)
	{
		if (value.Length is not (8 or 32))
		{
			return false;
		}

		ReadOnlySpan<byte> mask = value.Slice(value.Length / 2);
		int partial = mask.IndexOfAnyExcept((byte)0xFF);

		if (partial < 0)
		{
			return true;
		}

		// The first octet that is not all ones is a prefix of ones, so its complement is a suffix of ones, and the rest are zeros.
		int complement = ~mask[partial] & 0xFF;
		return (complement & complement + 1) is 0 && !mask.Slice(partial + 1).ContainsAnyExcept((byte)0);
	}
}

// A dNSName of a certificate, in the form in which it may match a host name (RFC 9525, Sec. 6.3) and in which name constraints apply to it: a DNS name, or a wildcard, a first label of "*" alone, before a DNS name, Base. Others are not valid, such as one with a trailing dot, an empty label, a space, a "*" in another place or "*" alone: they match nothing, and cannot be checked.
internal readonly struct DnsNamePattern
{
	public DnsNamePattern(string value)
	{
		Value = value;
		IsWildcard = value.StartsWith("*.", StringComparison.Ordinal);
		Base = IsWildcard ? value.Substring(2) : value;
		IsValid = HostName.IsDnsName(Base);
	}

	public string Value { get; }

	public string Base { get; }

	public bool IsWildcard { get; }

	public bool IsValid { get; }
}

// An Internet mail address of a certificate: Mailbox = Local-part "@" Domain (RFC 5321, Sec. 4.1.2), whose local part is a Dot-string and whose domain is a DNS name. A quoted local part or an address literal is not supported, and cannot be checked.
internal readonly record struct Mailbox(string LocalPart, string Domain)
{
	// atext (RFC 5322, Sec. 3.2.3).
	private static readonly SearchValues<char> AtomCharacters = SearchValues.Create("!#$%&'*+-/0123456789=?ABCDEFGHIJKLMNOPQRSTUVWXYZ^_`abcdefghijklmnopqrstuvwxyz{|}~");

	public static Mailbox? Parse(string value)
	{
		int at = value.IndexOf('@');

		if (at <= 0 || value.IndexOf('@', at + 1) >= 0)
		{
			return null;
		}

		string localPart = value.Substring(0, at);
		string domain = value.Substring(at + 1);
		return IsDotString(localPart) && HostName.IsDnsName(domain) ? new Mailbox(localPart, domain) : null;
	}

	// Dot-string = Atom *("." Atom), Atom = 1*atext.
	private static bool IsDotString(ReadOnlySpan<char> value)
	{
		foreach (Range atom in value.Split('.'))
		{
			ReadOnlySpan<char> characters = value[atom];

			if (characters.IsEmpty || characters.ContainsAnyExcept(AtomCharacters))
			{
				return false;
			}
		}

		return true;
	}
}

// An rfc822Name subtree (RFC 5280, Sec. 4.2.1.10): a mailbox, every mailbox at a host, or with a leading period every mailbox in the domain below it; or empty for every mailbox.
internal readonly struct MailboxConstraint
{
	private readonly Kind _kind;
	private readonly string _localPart;
	private readonly string _domain;

	private MailboxConstraint(Kind kind, string localPart, string domain)
	{
		_kind = kind;
		_localPart = localPart;
		_domain = domain;
	}

	private enum Kind
	{
		All,
		Mailbox,
		Host,
		Domain
	}

	public static MailboxConstraint? Parse(string value)
	{
		if (value.Length is 0)
		{
			return new MailboxConstraint(Kind.All, "", "");
		}

		if (value.Contains('@'))
		{
			return Mailbox.Parse(value) is { } mailbox ? new MailboxConstraint(Kind.Mailbox, mailbox.LocalPart, mailbox.Domain) : null;
		}

		if (value[0] is '.')
		{
			string domain = value.Substring(1);
			return HostName.IsDnsName(domain) ? new MailboxConstraint(Kind.Domain, "", domain) : null;
		}

		return HostName.IsDnsName(value) ? new MailboxConstraint(Kind.Host, "", value) : null;
	}

	// The local part matches exactly and the host ignoring the case of ASCII letters, as RFC 5280, Sec. 7.5, compares mail addresses.
	public bool Permits(Mailbox mailbox)
	{
		return _kind switch
		{
			Kind.All => true,
			Kind.Mailbox => mailbox.LocalPart == _localPart && Ascii.EqualsIgnoreCase(mailbox.Domain, _domain),
			Kind.Host => Ascii.EqualsIgnoreCase(mailbox.Domain, _domain),
			_ => mailbox.Domain.Length > _domain.Length && NameSubtrees.IsWithin(mailbox.Domain, _domain)
		};
	}
}

// The names of a certificate that name constraints apply to (RFC 5280, Sec. 6.1.3 (b) and (c)): those of the subject alternative name extension, the subject, and without that extension the emailAddress attributes of the subject (Sec. 4.2.1.10).
// An instance serves one validation, on one thread.
internal sealed class ConstrainedNames
{
	private readonly int _forms;
	private readonly ReadOnlyMemory<byte> _subject;
	private readonly ReadOnlyMemory<byte>[] _alternativeDirectoryNames;

	private ConstrainedNames(DnsNamePattern[] dnsNames, ReadOnlyMemory<byte>[] addresses, Mailbox?[] mailboxes, ReadOnlyMemory<byte> subject, ReadOnlyMemory<byte>[] alternativeDirectoryNames, int forms)
	{
		DnsNames = dnsNames;
		IPAddresses = addresses;
		Mailboxes = mailboxes;
		_subject = subject;
		_alternativeDirectoryNames = alternativeDirectoryNames;
		_forms = forms;
	}

	public DnsNamePattern[] DnsNames { get; }

	// IPv4 addresses in 4 octets and IPv6 addresses in 16.
	public ReadOnlyMemory<byte>[] IPAddresses { get; }

	// The mail addresses, or null for one that is not a valid mailbox.
	public Mailbox?[] Mailboxes { get; }

	// The directory names: a nonempty subject, then those of the subject alternative name extension. They are read the first time that directoryName subtrees apply, which few paths have.
	public DistinguishedName[] DirectoryNames => field ??= ReadDirectoryNames();

	public bool HasForm(GeneralNameType form)
	{
		return (_forms & 1 << (int)form) is not 0;
	}

	// The names of a certificate whose subject alternative name extension, if any, decodes. The DNS names and IP addresses are those that SubjectAlternativeName decoded, in the order of the extension.
	public static ConstrainedNames Create(Certificate certificate, SubjectAlternativeName? alternativeName)
	{
		List<Mailbox?> mailboxes = [];
		int forms = 0;

		if (alternativeName is null)
		{
			AddEmailAddresses(certificate.Subject, mailboxes);
			return new ConstrainedNames([], [], [.. mailboxes], certificate.Subject, [], forms);
		}

		IReadOnlyList<GeneralName> names = alternativeName.Names;
		List<ReadOnlyMemory<byte>> directoryNames = [];

		for (int i = 0; i < names.Count; ++i)
		{
			GeneralName name = names[i];
			forms |= 1 << (int)name.Type;

			if (name.Type is GeneralNameType.Rfc822Name)
			{
				mailboxes.Add(Mailbox.Parse(Encoding.ASCII.GetString(name.Value.Span)));
			}
			else if (name.Type is GeneralNameType.DirectoryName)
			{
				directoryNames.Add(name.Value);
			}
		}

		return new ConstrainedNames(alternativeName.DnsNamePatterns, [.. alternativeName.IPAddresses], [.. mailboxes], certificate.Subject, [.. directoryNames], forms);
	}

	private DistinguishedName[] ReadDirectoryNames()
	{
		bool hasSubject = !X509Name.IsEmpty(_subject.Span);
		DistinguishedName[] names = new DistinguishedName[(hasSubject ? 1 : 0) + _alternativeDirectoryNames.Length];
		int count = 0;

		if (hasSubject)
		{
			names[count++] = DistinguishedName.Read(_subject);
		}

		foreach (ReadOnlyMemory<byte> name in _alternativeDirectoryNames)
		{
			names[count++] = DistinguishedName.Read(name);
		}

		return names;
	}

	// The emailAddress attributes, EmailAddress ::= IA5String (RFC 5280, Appendix A.1), of a Name that decodes, as Certificate requires.
	private static void AddEmailAddresses(ReadOnlyMemory<byte> name, List<Mailbox?> mailboxes)
	{
		DerReader reader = new(name);
		DerReader relativeNames = reader.ReadSequence();

		while (relativeNames.HasData)
		{
			DerReader relativeName = relativeNames.ReadSetOf();

			while (relativeName.HasData)
			{
				DerReader attribute = relativeName.ReadSequence();

				if (!attribute.ReadObjectIdentifierContents().Span.SequenceEqual(DistinguishedName.EmailAddressOid))
				{
					continue;
				}

				ReadOnlySpan<byte> value = attribute.ReadEncodedValue().Span;

				try
				{
					ValueAsnReader text = new(value, AsnEncodingRules.DER);
					string address = text.ReadCharacterString(UniversalTagNumber.IA5String);
					mailboxes.Add(text.HasData ? null : Mailbox.Parse(address));
				}
				catch (AsnContentException)
				{
					mailboxes.Add(null);
				}
			}
		}
	}
}
