#if !NET11_0_OR_GREATER
namespace System.Runtime.CompilerServices;

// The attribute that the compiler puts on a union, which .NET 11 defines.
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct)]
internal sealed class UnionAttribute : Attribute;

// The interface that the compiler implements on a union, which .NET 11 defines.
internal interface IUnion
{
	object? Value { get; }
}
#endif
