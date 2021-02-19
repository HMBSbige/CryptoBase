using CryptoBase.Abstractions;
using CryptoBase.Abstractions.SymmetricCryptos;
using System;
using System.Buffers;

namespace CryptoBase.SymmetricCryptos.StreamCryptos
{
	public abstract class SnuffleCrypto : SnuffleCryptoBase, IIntrinsics
	{
		public abstract bool IsSupport { get; }

		/// <summary>
		/// expand 16-byte k
		/// </summary>
		protected static readonly uint[] Sigma16 = { 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 };

		/// <summary>
		/// expand 32-byte k
		/// </summary>
		protected static readonly uint[] Sigma32 = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };

		protected byte Rounds { get; init; } = 20;

		protected readonly uint[] State;
		protected readonly byte[] KeyStream;

		protected readonly ReadOnlyMemory<byte> Key;
		protected readonly ReadOnlyMemory<byte> Iv;

		protected int Index;

		protected SnuffleCrypto(byte[] key, byte[] iv) : base(key, iv)
		{
			Key = key;
			Iv = iv;

			State = ArrayPool<uint>.Shared.Rent(StateSize);
			KeyStream = ArrayPool<byte>.Shared.Rent(StateSize * sizeof(uint));
		}

		public override void Dispose()
		{
			base.Dispose();

			ArrayPool<uint>.Shared.Return(State);
			ArrayPool<byte>.Shared.Return(KeyStream);
		}
	}
}
