namespace CryptoBase.Hashes.Blake3;

// One item of parallel hashing: a whole subtree, hashed to the chaining values of its top node's two children, or one leaf of a subtree cut into several.
internal readonly record struct Blake3Leaf(int Subtree, int Start, int Length, bool IsWholeSubtree);
