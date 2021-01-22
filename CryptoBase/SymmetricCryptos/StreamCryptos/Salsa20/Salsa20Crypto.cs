using CryptoBase.Abstractions.SymmetricCryptos;
using System;
using System.Buffers;
using System.Runtime.CompilerServices;

namespace CryptoBase.SymmetricCryptos.StreamCryptos.Salsa20
{
	public abstract class Salsa20Crypto : Salsa20CryptoBase
	{
		protected readonly uint[] State;
		private readonly byte[] _keyStream;

		protected readonly ReadOnlyMemory<byte> Key;
		protected readonly ReadOnlyMemory<byte> Iv;

		protected byte Rounds { get; init; } = 20;

		protected int Index;

		/// <summary>
		/// expand 16-byte k
		/// </summary>
		protected readonly static uint[] Sigma16 = { 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 };

		/// <summary>
		/// expand 32-byte k
		/// </summary>
		protected readonly static uint[] Sigma32 = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

		protected Salsa20Crypto(byte[] key, byte[] iv) : base(key, iv)
		{
			Key = key;
			Iv = iv;

			State = ArrayPool<uint>.Shared.Rent(StateSize);
			_keyStream = ArrayPool<byte>.Shared.Rent(StateSize * sizeof(uint));
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining | MethodImplOptions.AggressiveOptimization)]
		protected override unsafe void Update(ReadOnlySpan<byte> source, Span<byte> destination)
		{
			if (destination.Length < source.Length)
			{
				throw new ArgumentException(string.Empty, nameof(destination));
			}

			while (source.Length > 0)
			{
				if (Index == 0)
				{
					UpdateKeyStream(State, _keyStream);
				}

				var r = _keyStream.AsSpan(Index);

				fixed (byte* pStream = r)
				fixed (byte* pSource = source)
				fixed (byte* pDestination = destination)
				{
					IntrinsicsUtils.Xor(pStream, pSource, pDestination, Math.Min(r.Length, source.Length));
				}

				if (source.Length < r.Length)
				{
					Index += source.Length;
					return;
				}

				Index = 0;
				source = source.Slice(r.Length);
				destination = destination.Slice(r.Length);
			}
		}

		protected abstract void UpdateKeyStream(uint[] state, byte[] keyStream);

		public override void Dispose()
		{
			base.Dispose();

			ArrayPool<uint>.Shared.Return(State);
			ArrayPool<byte>.Shared.Return(_keyStream);
		}
	}
}
