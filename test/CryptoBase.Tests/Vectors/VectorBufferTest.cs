using CryptoBase.Abstractions.Vectors;
using System.Runtime.CompilerServices;

namespace CryptoBase.Tests.Vectors;

public class VectorBufferTest
{
	[Test]
	public async Task ShouldNotBeByRefLike()
	{
		await Check<VectorBuffer16>(16);
		await Check<VectorBuffer32>(32);
		await Check<VectorBuffer64>(64);
		await Check<VectorBuffer128>(128);
		await Check<VectorBuffer256>(256);
		await Check<VectorBuffer512>(512);
		await Check<VectorBuffer1024>(1024);

		static async Task Check<T>(int expectedSize) where T : struct, allows ref struct
		{
			await Assert.That(typeof(T).IsByRefLike).IsFalse();
			await Assert.That(Unsafe.SizeOf<T>()).IsEqualTo(expectedSize);
		}
	}

	[Test]
	[Repeat(10)]
	public async Task WriteReturnValueToHeapBufferAcrossCompactingGC()
	{
		byte[] buffer = GC.AllocateUninitializedArray<byte>(16);

		Unsafe.WriteUnaligned(ref buffer[0], Make());

		await Assert.That(Unsafe.ReadUnaligned<ulong>(ref buffer[0])).IsEqualTo(0xDEADBEEFCAFEBABEUL);
		await Assert.That(Unsafe.ReadUnaligned<ulong>(ref buffer[8])).IsEqualTo(0x0123456789ABCDEFUL);
	}

	[Test]
	[Repeat(10)]
	public async Task AssignReturnValueToHeapBufferAcrossCompactingGC()
	{
		byte[] buffer = GC.AllocateUninitializedArray<byte>(16);

		ref VectorBuffer16 target = ref buffer.AsSpan().AsVectorBuffer16();
		target = Make();

		await Assert.That(Unsafe.ReadUnaligned<ulong>(ref buffer[0])).IsEqualTo(0xDEADBEEFCAFEBABEUL);
		await Assert.That(Unsafe.ReadUnaligned<ulong>(ref buffer[8])).IsEqualTo(0x0123456789ABCDEFUL);
	}

	[MethodImpl(MethodImplOptions.NoInlining)]
	private static VectorBuffer16 Make()
	{
		GC.Collect(2, GCCollectionMode.Forced, true, true);
		return new VectorBuffer16
		{
			Lower = 0xDEADBEEFCAFEBABEUL,
			Upper = 0x0123456789ABCDEFUL
		};
	}
}
