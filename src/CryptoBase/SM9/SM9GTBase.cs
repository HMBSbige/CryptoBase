using CryptoBase.EllipticCurves;
using CryptoBase.EllipticCurves.SM9;

namespace CryptoBase.SM9;

// The public base g of the powers of a master public key, e(P1, Ppub-s) of a signature one or e(Ppub-e, P2) of an encryption one. The first power goes without a table, which a key that takes one power has no use for, and a later one builds it. Threads that take powers at once may each build one, but only the first to finish publishes it, and the powers with and without it agree.
internal sealed class SM9GTBase : IDisposable
{
	private readonly SM9Fp12 _value;
	private SM9GTTable? _table;
	private bool _used;

	internal SM9GTBase(in SM9Fp12 value)
	{
		_value = value;
	}

	// The base e(p, q), or the one that another thread published in slot first.
	internal static SM9GTBase Publish(ref SM9GTBase? slot, in SM9AffinePoint<SM9Fp> p, in SM9AffinePoint<SM9Fp2> q)
	{
		SM9Pairing.Pair(in p, in q, out SM9Fp12 g);
		SM9GTBase value = new(in g);
		return Interlocked.CompareExchange(ref slot, value, null) ?? value;
	}

	// g^k. Neither the time nor the addresses depend on k; whether the table is used depends on the number of powers alone.
	internal void Power(in FieldElement<SM9Order> exponent, out SM9Fp12 result)
	{
		if (GetTable() is { } table)
		{
			table.Power(in exponent, out result);
		}
		else
		{
			SM9GT.Power(in _value, in exponent, out result);
		}
	}

	public void Dispose()
	{
		_table?.Dispose();
	}

	private SM9GTTable? GetTable()
	{
		SM9GTTable? table = _table;

		if (table is null && !_used)
		{
			_used = true;
			return null;
		}

		return table ?? PublishTable();
	}

	private SM9GTTable PublishTable()
	{
		SM9GTTable table = new(in _value);
		return Interlocked.CompareExchange(ref _table, table, null) ?? table;
	}
}
