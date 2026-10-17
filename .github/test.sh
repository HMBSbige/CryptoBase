#!/usr/bin/env bash
# Runs the Release tests with full optimization, from the repository root.
#   DISABLE   Comma-separated DOTNET_Enable<name> switches to turn off; Vector512 caps vectors at 256 bits instead.
#   SDE_PATH  Intel SDE kit; the tests run under "sde64 -spr" when SDE adds instruction sets this runner lacks.
set -eo pipefail

export DOTNET_TieredCompilation=0

for feature in ${DISABLE//,/ }; do
	case $feature in
		Vector512) export DOTNET_PreferredVectorBitWidth=256 ;;
		*) export "DOTNET_Enable$feature=0" ;;
	esac
done

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

"${runner[@]}" artifacts/bin/CryptoBase.Tests/release/CryptoBase.Tests.dll --minimum-expected-tests 1
