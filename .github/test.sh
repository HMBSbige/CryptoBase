#!/usr/bin/env bash
# Runs the tests from the repository root: optimized Release by default, "tiered" for tiered compilation, "debug" for Debug.
#   DISABLE   Comma-separated DOTNET_Enable<name> switches to turn off; Vector512 caps vectors at 256 bits instead.
#   SDE_PATH  Intel SDE kit; the default mode runs under "sde64 -spr" when SDE adds instruction sets this runner lacks.
#   SHARD     hashes, ciphers or rest: runs only that shard.
set -eo pipefail

tests=artifacts/bin/CryptoBase.Tests/release/CryptoBase.Tests.dll

# Filters cannot negate, so rest lists every other namespace.
shard_filter() {
	case $1 in
		hashes) echo '/*/CryptoBase.Tests.Hashes*/*/*' ;;
		ciphers) echo '/*/CryptoBase.Tests.Ciphers*/*/*' ;;
		rest) echo "/*/(CryptoBase.Tests)$(printf '|(CryptoBase.Tests.%s*)' Cavp DataFormatExtensions IO Kdf Kems Macs Platform Signatures Vectors Wycheproof)/*/*" ;;
		*) echo "Unknown shard: $1" >&2; return 1 ;;
	esac
}

# Prints the namespaces of the tests that a filter selects.
namespaces() {
	dotnet "$tests" --list-tests json --treenode-filter "$1" --ignore-exit-code 8 | awk -F'"' '$2 == "namespace" { print $4 }' | sort -u
}

for feature in ${DISABLE//,/ }; do
	case $feature in
		Vector512) export DOTNET_PreferredVectorBitWidth=256 ;;
		*) export "DOTNET_Enable$feature=0" ;;
	esac
done

filter=()

if [[ -n $SHARD ]]; then
	shard=$(shard_filter "$SHARD")
	filter=(--treenode-filter "$shard")
fi

case $1 in
	'') ;;
	tiered) exec dotnet "$tests" --minimum-expected-tests 1 "${filter[@]}" ;;
	debug) exec dotnet test --project test/CryptoBase.Tests -c Debug --minimum-expected-tests 1 "${filter[@]}" ;;
	*) echo "Unknown mode: $1" >&2; exit 1 ;;
esac

# A namespace missing from rest would go untested. The wildcard filter, like the shards, leaves out explicit tests.
if [[ -n $SHARD ]]; then
	all=$(namespaces '/*/*/*/*')
	sharded=$(for name in hashes ciphers rest; do namespaces "$(shard_filter "$name")"; done | sort)

	if [[ -z $all || $all != "$sharded" ]]; then
		echo 'Each namespace must be in exactly one shard (< missing, > repeated):' >&2
		diff <(echo "$all") <(echo "$sharded") >&2
		exit 1
	fi
fi

export DOTNET_TieredCompilation=0
runner=(dotnet)

if [[ -n $SDE_PATH ]]; then
	sde=("$SDE_PATH/sde64" -spr --)
	probe=artifacts/bin/InstructionSets/InstructionSets.dll
	dotnet build .github/InstructionSets.cs -c Release -o "${probe%/*}" -v q
	native=$(dotnet "$probe")
	emulated=$(DOTNET_EnableDiagnostics=0 "${sde[@]}" dotnet "$probe")
	missing=$(LC_ALL=C comm -13 <(echo "$native") <(echo "$emulated") | paste -sd ' ')
	echo "CPU:$(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2); SDE adds: ${missing:-nothing}"

	if [[ -n $missing ]]; then
		runner=("${sde[@]}" dotnet)
		export DOTNET_EnableDiagnostics=0
		# SDE loses emulated vector registers across signal handlers:
		# https://web.archive.org/web/20260113162404/https://community.intel.com/t5/Intel-ISA-Extensions/SDE-signal-handling-bug/td-p/1646699
		# The runtime signals threads to suspend them for GC; make GC wait for them to poll instead.
		export DOTNET_INTERNAL_ThreadSuspendInjection=0
		# Keep glibc and OpenSSL off emulated AVX-512, which is slow and exposed to the same bug.
		export GLIBC_TUNABLES=glibc.cpu.hwcaps=-AVX512F,-AVX512VL,-AVX512BW,-AVX512DQ,-AVX512CD
		export OPENSSL_ia32cap=:~0x600C0230000
	fi
fi

"${runner[@]}" "$tests" --minimum-expected-tests 1 "${filter[@]}"
