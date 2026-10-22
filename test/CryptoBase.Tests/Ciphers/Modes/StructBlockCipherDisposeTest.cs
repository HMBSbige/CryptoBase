using CryptoBase.Abstractions.Ciphers;
using CryptoBase.Ciphers.Modes;
using System.Runtime.CompilerServices;

namespace CryptoBase.Tests.Ciphers.Modes;

public class StructBlockCipherDisposeTest
{
	private static readonly byte[] Key = Enumerable.Range(1, 32).Select(static value => (byte)value).ToArray();

	[Test]
	public async Task CcmDisposesStoredCipher()
	{
		CcmMode<InlineKeyBlockCipher> mode = CcmMode<InlineKeyBlockCipher>.Create(Key.AsSpan(0, 16));
		await Assert.That(EncryptorFields<InlineKeyBlockCipher>.Ccm(mode).IsWiped).IsFalse();

		mode.Dispose();

		await Assert.That(EncryptorFields<InlineKeyBlockCipher>.Ccm(mode).IsWiped).IsTrue();
	}

	[Test]
	public async Task Ccm8DisposesStoredCipher()
	{
		Ccm8Mode<InlineKeyBlockCipher> mode = Ccm8Mode<InlineKeyBlockCipher>.Create(Key.AsSpan(0, 16));
		await Assert.That(EncryptorFields<InlineKeyBlockCipher>.Ccm8(mode).IsWiped).IsFalse();

		mode.Dispose();

		await Assert.That(EncryptorFields<InlineKeyBlockCipher>.Ccm8(mode).IsWiped).IsTrue();
	}

	[Test]
	public async Task GcmDisposesStoredCipher()
	{
		GcmMode<InlineKeyBlockCipher> mode = GcmMode<InlineKeyBlockCipher>.Create(Key.AsSpan(0, 16));
		await Assert.That(EncryptorFields<InlineKeyBlockCipher>.Gcm(mode).IsWiped).IsFalse();

		mode.Dispose();

		await Assert.That(EncryptorFields<InlineKeyBlockCipher>.Gcm(mode).IsWiped).IsTrue();
	}

	[Test]
	public async Task CtrDisposesStoredCipher()
	{
		CtrMode128<InlineKeyBlockCipher> mode = CtrMode128<InlineKeyBlockCipher>.Create(Key.AsSpan(0, 16), new byte[16]);
		await Assert.That(EncryptorFields<InlineKeyBlockCipher>.Ctr(mode).IsWiped).IsFalse();

		mode.Dispose();

		await Assert.That(EncryptorFields<InlineKeyBlockCipher>.Ctr(mode).IsWiped).IsTrue();
	}

	[Test]
	public async Task XtsDisposesBothStoredCiphers()
	{
		XtsMode<InlineKeyBlockCipher> mode = XtsMode<InlineKeyBlockCipher>.Create(Key);

		using (Assert.Multiple())
		{
			await Assert.That(CipherFields<InlineKeyBlockCipher>.XtsData(mode).IsWiped).IsFalse();
			await Assert.That(CipherFields<InlineKeyBlockCipher>.XtsTweak(mode).IsWiped).IsFalse();
		}

		mode.Dispose();

		using (Assert.Multiple())
		{
			await Assert.That(CipherFields<InlineKeyBlockCipher>.XtsData(mode).IsWiped).IsTrue();
			await Assert.That(CipherFields<InlineKeyBlockCipher>.XtsTweak(mode).IsWiped).IsTrue();
		}
	}

	[Test]
	public async Task DisposingTwiceReleasesEachStoredCipherOnce()
	{
		using (Assert.Multiple())
		{
			await Assert.That(CountReleasesAfterDisposingTwice(static () => CcmMode<ReleaseCountingBlockCipher>.Create(Key.AsSpan(0, 16)))).IsEqualTo(1);
			await Assert.That(CountReleasesAfterDisposingTwice(static () => Ccm8Mode<ReleaseCountingBlockCipher>.Create(Key.AsSpan(0, 16)))).IsEqualTo(1);
			await Assert.That(CountReleasesAfterDisposingTwice(static () => GcmMode<ReleaseCountingBlockCipher>.Create(Key.AsSpan(0, 16)))).IsEqualTo(1);
			await Assert.That(CountReleasesAfterDisposingTwice(static () => CtrMode128<ReleaseCountingBlockCipher>.Create(Key.AsSpan(0, 16), new byte[16]))).IsEqualTo(1);
			await Assert.That(CountReleasesAfterDisposingTwice(static () => XtsMode<ReleaseCountingBlockCipher>.Create(Key))).IsEqualTo(2);
		}
	}

	private static int CountReleasesAfterDisposingTwice(Func<IDisposable> create)
	{
		IDisposable mode = create();
		int before = ReleaseCountingBlockCipher.ReleaseCount;
		mode.Dispose();
		mode.Dispose();
		return ReleaseCountingBlockCipher.ReleaseCount - before;
	}

	private static class EncryptorFields<TBlockCipher> where TBlockCipher : IBlockEncryptor<TBlockCipher>
	{
		[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_blockCipher")]
		public static extern ref TBlockCipher Ccm(CcmMode<TBlockCipher> mode);

		[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_blockCipher")]
		public static extern ref TBlockCipher Ccm8(Ccm8Mode<TBlockCipher> mode);

		[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_blockCipher")]
		public static extern ref TBlockCipher Gcm(GcmMode<TBlockCipher> mode);

		[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_blockCipher")]
		public static extern ref TBlockCipher Ctr(CtrMode128<TBlockCipher> mode);
	}

	private static class CipherFields<TBlockCipher> where TBlockCipher : IBlockCipher<TBlockCipher>
	{
		[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_dataCipher")]
		public static extern ref TBlockCipher XtsData(XtsMode<TBlockCipher> mode);

		[UnsafeAccessor(UnsafeAccessorKind.Field, Name = "_tweakCipher")]
		public static extern ref TBlockCipher XtsTweak(XtsMode<TBlockCipher> mode);
	}

	[InlineArray(16)]
	private struct InlineKey
	{
		private byte _element0;
	}

	// A value-type cipher whose key lives inside the struct, so only disposing the stored instance wipes it.
	private struct InlineKeyBlockCipher : IBlockCipher<InlineKeyBlockCipher>
	{
		private InlineKey _key;

		public static int BlockSize => 16;

		public readonly bool IsWiped => !((ReadOnlySpan<byte>)_key).ContainsAnyExcept((byte)0);

		public static InlineKeyBlockCipher Create(scoped ReadOnlySpan<byte> key)
		{
			InlineKeyBlockCipher cipher = default;
			key.Slice(0, 16).CopyTo(cipher._key);
			return cipher;
		}

		public readonly void EncryptBlock(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
		{
			EncryptBlocks(source.Slice(0, 16), destination);
		}

		public readonly void EncryptBlocks(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
		{
			ReadOnlySpan<byte> key = _key;

			for (int i = 0; i < source.Length; ++i)
			{
				destination[i] = (byte)(source[i] ^ key[i % 16]);
			}
		}

		public readonly void DecryptBlock(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
		{
			EncryptBlock(source, destination);
		}

		public readonly void DecryptBlocks(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
		{
			EncryptBlocks(source, destination);
		}

		public void Dispose()
		{
			((Span<byte>)_key).Clear();
		}
	}

	// Dispose releases once per instance, so disposing a defensive copy would release again on the second call.
	private struct ReleaseCountingBlockCipher : IBlockCipher<ReleaseCountingBlockCipher>
	{
		private static int _releaseCount;

		private bool _released;

		public static int BlockSize => 16;

		internal static int ReleaseCount => Volatile.Read(ref _releaseCount);

		public static ReleaseCountingBlockCipher Create(scoped ReadOnlySpan<byte> key)
		{
			return default;
		}

		public readonly void EncryptBlock(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
		{
			source.Slice(0, 16).CopyTo(destination);
		}

		public readonly void EncryptBlocks(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
		{
			source.CopyTo(destination);
		}

		public readonly void DecryptBlock(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
		{
			EncryptBlock(source, destination);
		}

		public readonly void DecryptBlocks(scoped ReadOnlySpan<byte> source, scoped Span<byte> destination)
		{
			EncryptBlocks(source, destination);
		}

		public void Dispose()
		{
			if (_released)
			{
				return;
			}

			_released = true;
			Interlocked.Increment(ref _releaseCount);
		}
	}
}
