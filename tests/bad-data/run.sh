#!/bin/sh
#
# Bad-data tests for the M4 preprocessing stage of modular policy builds:
# .if -> all_interfaces.conf, .te + interfaces -> .tmp, .fc -> .mod.fc
#
# Mirrors Rules.modular invocations; uses plain "module name 1.0;" fixtures so tests
# do not depend on generated_definitions.conf.
#

set -u

BASEDIR=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
POLICY_ROOT=$(CDPATH= cd -- "${BASEDIR}/../.." && pwd)
FIXTURES="${BASEDIR}/fixtures"
OUTDIR=$(mktemp -d "${TMPDIR:-/tmp}/selinux-policy-bad-data.XXXXXX")
PASS=0
FAIL=0

M4=${M4:-m4}
CHECKMODULE=${CHECKMODULE:-checkmodule}
MAKE=${MAKE:-make}
SEMODULE_PACKAGE=${SEMODULE_PACKAGE:-semodule_package}

M4SUPPORT="${POLICY_ROOT}/support/divert.m4 \
	${POLICY_ROOT}/policy/support/misc_macros.spt \
	${POLICY_ROOT}/policy/support/mls_mcs_macros.spt \
	${POLICY_ROOT}/policy/support/loadable_module.spt \
	${POLICY_ROOT}/policy/support/obj_perm_sets.spt \
	${POLICY_ROOT}/support/undivert.m4"

M4PARAM="-D enable_mcs -D distro_redhat -D hide_broken_symptoms -D mls_num_sens=16 -D mls_num_cats=1024 -D mcs_num_cats=1024"

IFERROR="${POLICY_ROOT}/support/iferror.m4"
EMPTY_GEN_DEF=/dev/null

cleanup() {
	rm -rf "${OUTDIR}"
}
trap cleanup EXIT

die() {
	echo "FAIL: $*" >&2
	FAIL=$((FAIL + 1))
}

pass() {
	echo "==== $*"
	PASS=$((PASS + 1))
	echo ""
}

# Build all_interfaces.conf from one or more .if files (Rules.modular lines 138-143).
build_all_interfaces() {
	out="$1"
	shift

	echo 'divert(-1)' >"${out}"
	# shellcheck disable=SC2086
	set +e
	${M4} ${M4PARAM} ${M4SUPPORT} "$@" "${IFERROR}" >"${out}.tmp" 2>"${out}.err"
	rc=$?
	sed -e 's/dollarsstar/$*/g' "${out}.tmp" >>"${out}"
	echo 'divert' >>"${out}"
	set +e
	return "${rc}"
}

# Expand a module .te with interfaces (Rules.modular line 73-76; /dev/null for gen defs).
expand_module_te() {
	interfaces="$1"
	te="$2"
	out="$3"

	# shellcheck disable=SC2086
	set +e
	${M4} ${M4PARAM} -s ${M4SUPPORT} "${EMPTY_GEN_DEF}" "${interfaces}" "${te}" \
		>"${out}" 2>"${out}.err"
	rc=$?
	set +e
	return "${rc}"
}

# Expand file_contexts (Rules.modular line 79-81).
expand_fc() {
	fc="$1"
	out="$2"

	# shellcheck disable=SC2086
	set +e
	${M4} ${M4PARAM} ${M4SUPPORT} "${fc}" >"${out}" 2>"${out}.err"
	rc=$?
	set +e
	return "${rc}"
}

mod_name_from_te() {
	sed -n 's/^module[[:space:]]\+\([^[:space:]]\+\).*/\1/p' "$1" | head -1
}

expect_m4_interfaces_fail() {
	desc="$1"
	name="$2"
	shift 2

	echo "==== NEGATIVE (expect M4 interface build failure): ${desc}"
	out="${OUTDIR}/${name}.interfaces"
	rm -f "${out}" "${out}.tmp" "${out}.err"

	set +e
	build_all_interfaces "${out}" "$@"
	rc=$?
	set -e

	if [ "${rc}" -eq 0 ]; then
		die "${desc}: expected non-zero M4 exit, got rc=0"
		return 0
	fi

	pass "${desc} (M4 failed as expected, rc=${rc})"
}

expect_m4_interfaces_fail_unreadable() {
	desc="unreadable .if file"
	name="unreadable_if"
	if_path="${OUTDIR}/unreadable.if"
	out="${OUTDIR}/${name}.interfaces"

	echo "==== NEGATIVE (expect M4 interface build failure): ${desc}"
	if [ "$(id -u)" -eq 0 ]; then
		echo "SKIP: root can read mode 000 files; unreadable check is non-root only"
		PASS=$((PASS + 1))
		echo ""
		return 0
	fi

	rm -f "${out}" "${out}.tmp" "${out}.err"
	cp "${FIXTURES}/interfaces/good.if" "${if_path}"
	chmod 000 "${if_path}"

	set +e
	build_all_interfaces "${out}" "${if_path}"
	rc=$?
	set -e

	if [ "${rc}" -eq 0 ]; then
		die "${desc}: expected non-zero M4 exit, got rc=0"
		return 0
	fi

	pass "${desc} (M4 failed as expected, rc=${rc})"
}

expect_m4_interfaces_pass() {
	desc="$1"
	name="$2"
	shift 2

	echo "==== POSITIVE (expect M4 interface build success): ${desc}"
	out="${OUTDIR}/${name}.interfaces"
	rm -f "${out}" "${out}.tmp" "${out}.err"

	set +e
	build_all_interfaces "${out}" "$@"
	rc=$?
	set -e

	if [ "${rc}" -ne 0 ]; then
		echo "stderr:" >&2
		cat "${out}.err" >&2
		die "${desc}: expected M4 success, got rc=${rc}"
		return 1
	fi
	if [ ! -s "${out}" ]; then
		die "${desc}: expected non-empty ${out}"
		return 1
	fi

	pass "${desc} (M4 succeeded)"
}

expect_expand_pass() {
	desc="$1"
	name="$2"
	interfaces="$3"
	te="$4"

	echo "==== POSITIVE (expect module M4 expand success): ${desc}"
	tmp="${OUTDIR}/${name}.tmp"
	rm -f "${tmp}" "${tmp}.err"

	set +e
	expand_module_te "${interfaces}" "${te}" "${tmp}"
	rc=$?
	set -e

	if [ "${rc}" -ne 0 ]; then
		cat "${tmp}.err" >&2
		die "${desc}: expected M4 success, got rc=${rc}"
		return 1
	fi
	if [ ! -s "${tmp}" ]; then
		die "${desc}: expected non-empty ${tmp}"
		return 1
	fi

	pass "${desc} (M4 expand succeeded)"
}

expect_expand_fail() {
	desc="$1"
	name="$2"
	interfaces="$3"
	te="$4"

	echo "==== NEGATIVE (expect module M4 expand failure): ${desc}"
	tmp="${OUTDIR}/${name}.tmp"
	rm -f "${tmp}" "${tmp}.err"

	set +e
	expand_module_te "${interfaces}" "${te}" "${tmp}"
	rc=$?
	set -e

	if [ "${rc}" -eq 0 ]; then
		die "${desc}: expected M4 failure, got rc=0"
		return 1
	fi

	pass "${desc} (M4 expand failed as expected, rc=${rc})"
}

expect_make_missing_te_fail() {
	desc="Make fails when module .te is missing (Rules.modular primary path)"
	name="b31_missing_te"
	mod="bad_missing_te"
	moddir="${OUTDIR}/${name}_mod"
	makedir="${BASEDIR}/make-primary"
	out="${moddir}/out"
	log="${OUTDIR}/${name}.log"

	echo "==== NEGATIVE (expect Makefile failure): ${desc}"
	rm -rf "${moddir}"
	mkdir -p "${moddir}"
	cp "${FIXTURES}/make_primary/${mod}.if" "${moddir}/${mod}.if"
	cp "${FIXTURES}/make_primary/${mod}.fc" "${moddir}/${mod}.fc"

	rm -f "${log}"
	set +e
	${MAKE} -f "${makedir}/Makefile" \
		POLICY_ROOT="${POLICY_ROOT}" \
		MODDIR="${moddir}" \
		OUTDIR="${out}" \
		MOD="${mod}" \
		"${out}/${mod}.pp" >"${log}" 2>&1
	rc=$?
	set -e

	if [ "${rc}" -eq 0 ]; then
		cat "${log}" >&2
		die "${desc}: expected non-zero make exit, got rc=0"
		return 1
	fi
	if [ -f "${out}/${mod}.mod" ] || [ -f "${out}/${mod}.pp" ]; then
		die "${desc}: did not expect ${out}/${mod}.mod or .pp"
		return 1
	fi
	if ! grep -Eq "${mod}\\.te|No rule to make target|No such file" "${log}"; then
		echo "FAIL: make log did not mention missing ${mod}.te" >&2
		cat "${log}" >&2
		FAIL=$((FAIL + 1))
		return 0
	fi

	pass "${desc} (make failed as expected, rc=${rc})"
}

expect_m4_package_e2e_deferred() {
	desc="$1"
	name="$2"
	fc="$3"
	interfaces="$4"
	te="$5"

	modfc="${OUTDIR}/${name}.mod.fc"
	pp="${OUTDIR}/${name}.pp"
	tmp="${OUTDIR}/${name}.tmp"
	modname=$(mod_name_from_te "${te}")
	e2e_dir="${OUTDIR}/${name}_build"
	goodmod="${e2e_dir}/${modname}.mod"
	stderr="${OUTDIR}/${name}.err"

	echo "==== DOCUMENT (M4 to semodule_package E2E; validate in sefcontext_compile): ${desc}"
	if ! command -v "${SEMODULE_PACKAGE}" >/dev/null 2>&1; then
		die "${desc}: ${SEMODULE_PACKAGE} not found on PATH"
		return 1
	fi

	rm -rf "${e2e_dir}"
	mkdir -p "${e2e_dir}"
	rm -f "${modfc}" "${modfc}.err" "${pp}" "${stderr}" "${tmp}" "${tmp}.err"

	set +e
	expand_module_te "${interfaces}" "${te}" "${tmp}"
	rc=$?
	set -e
	if [ "${rc}" -ne 0 ]; then
		cat "${tmp}.err" >&2
		die "${desc}: expected M4 success for good .te, got rc=${rc}"
		return 1
	fi

	set +e
	"${CHECKMODULE}" -M -m -o "${goodmod}" "${tmp}" 2>"${stderr}"
	rc=$?
	set -e
	if [ "${rc}" -ne 0 ]; then
		cat "${stderr}" >&2
		die "${desc}: expected checkmodule success for good .mod, got rc=${rc}"
		return 1
	fi

	set +e
	expand_fc "${fc}" "${modfc}"
	rc=$?
	set -e
	if [ "${rc}" -ne 0 ]; then
		cat "${modfc}.err" >&2
		die "${desc}: expected M4 success for bad .fc, got rc=${rc}"
		return 1
	fi

	rm -f "${pp}"
	set +e
	"${SEMODULE_PACKAGE}" -o "${pp}" -m "${goodmod}" -f "${modfc}" 2>"${stderr}"
	rc=$?
	set -e

	if [ "${rc}" -ne 0 ]; then
		cat "${stderr}" >&2
		die "${desc}: expected semodule_package exit 0 at packaging stage, got rc=${rc}"
		return 1
	fi
	if [ ! -s "${pp}" ]; then
		die "${desc}: expected non-empty ${pp}"
		return 1
	fi

	pass "${desc} (M4 to package exit 0; labeling validation deferred to sefcontext_compile)"
}

expect_expand_then_checkmodule_pass() {
	desc="$1"
	name="$2"
	interfaces="$3"
	te="$4"

	expect_expand_pass "${desc}" "${name}" "${interfaces}" "${te}" || return 1

	tmp="${OUTDIR}/${name}.tmp"
	modname=$(mod_name_from_te "${te}")
	outmod="${OUTDIR}/${modname}.mod"
	stderr="${OUTDIR}/${modname}.err"

	echo "==== POSITIVE (expect checkmodule success after M4): ${desc}"
	rm -f "${outmod}"

	set +e
	"${CHECKMODULE}" -M -m -o "${outmod}" "${tmp}" 2>"${stderr}"
	rc=$?
	set -e

	if [ "${rc}" -ne 0 ]; then
		cat "${stderr}" >&2
		die "${desc}: expected checkmodule success, got rc=${rc}"
		return 1
	fi
	if [ ! -s "${outmod}" ]; then
		die "${desc}: expected non-empty ${outmod}"
		return 1
	fi

	pass "${desc} (checkmodule succeeded)"
}

expect_expand_then_checkmodule_fail() {
	desc="$1"
	name="$2"
	interfaces="$3"
	te="$4"

	expect_expand_pass "${desc} (M4 stage)" "${name}" "${interfaces}" "${te}" || return 1

	tmp="${OUTDIR}/${name}.tmp"
	modname=$(mod_name_from_te "${te}")
	outmod="${OUTDIR}/${modname}.mod"
	stderr="${OUTDIR}/${modname}.err"

	echo "==== NEGATIVE (expect checkmodule failure after M4): ${desc}"
	rm -f "${outmod}"

	set +e
	"${CHECKMODULE}" -M -m -o "${outmod}" "${tmp}" 2>"${stderr}"
	rc=$?
	set -e

	if [ "${rc}" -eq 0 ]; then
		die "${desc}: expected checkmodule failure, got rc=0"
		return 1
	fi

	pass "${desc} (checkmodule failed as expected, rc=${rc})"
}

expect_expand_then_checkmodule_pass_document() {
	desc="$1"
	name="$2"
	interfaces="$3"
	te="$4"
	note="$5"

	expect_expand_pass "${desc}" "${name}" "${interfaces}" "${te}" || return 1

	tmp="${OUTDIR}/${name}.tmp"
	modname=$(mod_name_from_te "${te}")
	outmod="${OUTDIR}/${modname}.mod"
	stderr="${OUTDIR}/${modname}.err"

	echo "==== DOCUMENT (${note}): ${desc}"
	rm -f "${outmod}"

	set +e
	"${CHECKMODULE}" -M -m -o "${outmod}" "${tmp}" 2>"${stderr}"
	rc=$?
	set -e

	if [ "${rc}" -ne 0 ]; then
		cat "${stderr}" >&2
		die "${desc}: expected checkmodule success, got rc=${rc}"
		return 1
	fi
	if [ ! -s "${outmod}" ]; then
		die "${desc}: expected non-empty ${outmod}"
		return 1
	fi

	pass "${desc} (M4 and checkmodule succeeded; ${note})"
}

expect_fc_m4_pass() {
	desc="$1"
	name="$2"
	fc="$3"

	echo "==== POSITIVE (expect .fc M4 pass): ${desc}"
	out="${OUTDIR}/${name}.mod.fc"
	rm -f "${out}" "${out}.err"

	set +e
	expand_fc "${fc}" "${out}"
	rc=$?
	set -e

	if [ "${rc}" -ne 0 ]; then
		cat "${out}.err" >&2
		die "${desc}: expected M4 success, got rc=${rc}"
		return 1
	fi
	if [ ! -s "${out}" ]; then
		die "${desc}: expected non-empty ${out}"
		return 1
	fi

	pass "${desc} (M4 produced output; labeling validation is post-.mod)"
}

expect_fc_m4_pass_deferred() {
	desc="$1"
	name="$2"
	fc="$3"
	allow_empty="${4:-0}"

	echo "==== DOCUMENT (M4 accepts input; validate in sefcontext_compile): ${desc}"
	out="${OUTDIR}/${name}.mod.fc"
	rm -f "${out}" "${out}.err"

	set +e
	expand_fc "${fc}" "${out}"
	rc=$?
	set -e

	if [ "${rc}" -ne 0 ]; then
		cat "${out}.err" >&2
		die "${desc}: expected M4 success at preprocessing stage, got rc=${rc}"
		return 1
	fi
	if [ "${allow_empty}" -eq 0 ] && [ ! -s "${out}" ]; then
		die "${desc}: expected non-empty ${out} at preprocessing stage"
		return 1
	fi

	pass "${desc} (M4 exit 0; labeling validation deferred to sefcontext_compile)"
}

expect_fc_m4_fail() {
	desc="$1"
	name="$2"
	fc="$3"

	echo "==== NEGATIVE (expect .fc M4 failure): ${desc}"
	out="${OUTDIR}/${name}.mod.fc"
	rm -f "${out}" "${out}.err"

	set +e
	expand_fc "${fc}" "${out}"
	rc=$?
	set -e

	if [ "${rc}" -eq 0 ]; then
		die "${desc}: expected M4 failure, got rc=0"
		return 1
	fi

	pass "${desc} (M4 failed as expected, rc=${rc})"
}

expect_fc_m4_fail_unreadable() {
	desc="unreadable .fc file"
	fc="${OUTDIR}/unreadable.fc"
	out="${OUTDIR}/unreadable_fc.mod.fc"

	echo "==== NEGATIVE (expect .fc M4 failure): ${desc}"
	if [ "$(id -u)" -eq 0 ]; then
		echo "SKIP: root can read mode 000 files; unreadable check is non-root only"
		PASS=$((PASS + 1))
		echo ""
		return 0
	fi

	rm -f "${out}" "${out}.err"
	cp "${FIXTURES}/file_contexts/good.fc" "${fc}"
	chmod 000 "${fc}"

	set +e
	expand_fc "${fc}" "${out}"
	rc=$?
	set -e

	if [ "${rc}" -eq 0 ]; then
		die "${desc}: expected non-zero M4 exit, got rc=0"
		return 0
	fi

	pass "${desc} (M4 failed as expected, rc=${rc})"
}

# Ephemeral path fixtures for interface and file_context tests.
ln -sf /nonexistent/test_good.if "${OUTDIR}/broken_symlink.if"
ln -sf /nonexistent/test_good.mod.fc "${OUTDIR}/broken_symlink.fc"
printf '' > "${OUTDIR}/empty.fc"

# --- .if -> all_interfaces.conf ---
expect_m4_interfaces_fail \
	"unclosed interface definition" \
	b1_unclosed \
	"${FIXTURES}/interfaces/bad_unclosed.if"

expect_m4_interfaces_fail \
	"broken M4 syntax in interface file" \
	b1_m4_syntax \
	"${FIXTURES}/interfaces/bad_m4_syntax.if"

expect_m4_interfaces_fail \
	"duplicate interface definition" \
	b1_duplicate \
	"${FIXTURES}/interfaces/bad_duplicate.if"

expect_m4_interfaces_fail \
	"broken gen_require block in interface file" \
	b1_bad_gen_if \
	"${FIXTURES}/interfaces/bad_gen_if_build.if"

expect_m4_interfaces_fail \
	"empty interface template name" \
	b1_empty_ifname \
	"${FIXTURES}/interfaces/bad_empty_ifname.if"

expect_m4_interfaces_fail \
	"missing .if path" \
	b1_missing \
	"${OUTDIR}/does_not_exist.if"

expect_m4_interfaces_fail \
	"directory instead of .if file" \
	b1_directory \
	"${BASEDIR}"

expect_m4_interfaces_fail \
	"broken symlink for .if" \
	b1_symlink \
	"${OUTDIR}/broken_symlink.if"

expect_m4_interfaces_fail_unreadable

expect_m4_interfaces_pass \
	"control good interface" \
	b1_good \
	"${FIXTURES}/interfaces/good.if"

# --- .te + M4 with interfaces ---
GOOD_IF="${OUTDIR}/b1_good.interfaces"

expect_expand_then_checkmodule_pass \
	"control good .if + .te through M4 and checkmodule" \
	b2_good \
	"${GOOD_IF}" \
	"${FIXTURES}/modules/te_good.te"

expect_expand_fail \
	"missing .te path at M4 expand" \
	b2_missing_te \
	"${GOOD_IF}" \
	"${OUTDIR}/does_not_exist.te"

expect_make_missing_te_fail

NEEDS_ARG_IF="${OUTDIR}/needs_arg.interfaces"
build_all_interfaces "${NEEDS_ARG_IF}" "${FIXTURES}/interfaces/needs_arg.if"

expect_expand_then_checkmodule_fail \
	"interface called with too few arguments" \
	b2_few_args \
	"${NEEDS_ARG_IF}" \
	"${FIXTURES}/modules/te_few_args.te"

expect_expand_then_checkmodule_pass_document \
	"interface called with too many arguments" \
	b2_many_args \
	"${NEEDS_ARG_IF}" \
	"${FIXTURES}/modules/te_many_args.te" \
	"extra interface args are ignored by M4"

# --- M4 OK, bad expanded TE -> checkmodule fails ---
TRUNC_IF="${OUTDIR}/bad_trunc.interfaces"
build_all_interfaces "${TRUNC_IF}" "${FIXTURES}/interfaces/bad_trunc.if"

expect_expand_then_checkmodule_fail \
	"truncated allow from interface expansion" \
	b5_trunc \
	"${TRUNC_IF}" \
	"${FIXTURES}/modules/te_trunc.te"

GEN_REQ_IF="${OUTDIR}/bad_gen_require.interfaces"
build_all_interfaces "${GEN_REQ_IF}" "${FIXTURES}/interfaces/bad_gen_require.if"

expect_expand_then_checkmodule_fail \
	"broken gen_require expanded from interface" \
	b5_gen_require \
	"${GEN_REQ_IF}" \
	"${FIXTURES}/modules/te_gen_require.te"

UNKNOWN_TYPE_IF="${OUTDIR}/bad_unknown_type.interfaces"
build_all_interfaces "${UNKNOWN_TYPE_IF}" \
	"${FIXTURES}/interfaces/bad_unknown_type.if"

expect_expand_then_checkmodule_fail \
	"unknown type from interface expansion" \
	b5_unknown_type \
	"${UNKNOWN_TYPE_IF}" \
	"${FIXTURES}/modules/te_unknown_type.te"

UNKNOWN_PERM_IF="${OUTDIR}/bad_unknown_perm.interfaces"
build_all_interfaces "${UNKNOWN_PERM_IF}" \
	"${FIXTURES}/interfaces/bad_unknown_perm.if"

expect_expand_then_checkmodule_fail \
	"unknown permission from interface expansion" \
	b5_unknown_perm \
	"${UNKNOWN_PERM_IF}" \
	"${FIXTURES}/modules/te_unknown_perm.te"

GARBAGE_IF="${OUTDIR}/bad_garbage.interfaces"
build_all_interfaces "${GARBAGE_IF}" "${FIXTURES}/interfaces/bad_garbage.if"

expect_expand_then_checkmodule_fail \
	"garbage token from interface expansion" \
	b5_garbage \
	"${GARBAGE_IF}" \
	"${FIXTURES}/modules/te_garbage.te"

MODULE_LINE_IF="${OUTDIR}/bad_module_line.interfaces"
build_all_interfaces "${MODULE_LINE_IF}" \
	"${FIXTURES}/interfaces/bad_module_line.if"

expect_expand_then_checkmodule_fail \
	"invalid module line from interface expansion" \
	b5_module_line \
	"${MODULE_LINE_IF}" \
	"${FIXTURES}/modules/te_bad_module_line.te"

# --- .fc -> M4 -> .mod.fc ---
expect_fc_m4_pass \
	"control good .fc through M4" \
	b3_good \
	"${FIXTURES}/file_contexts/good.fc"

expect_fc_m4_pass_deferred \
	"invalid context survives M4" \
	b3_bad_context \
	"${FIXTURES}/file_contexts/bad_context.fc"

expect_fc_m4_pass_deferred \
	"wrong field count in .fc" \
	b3_bad_fields \
	"${FIXTURES}/file_contexts/bad_fields.fc"

expect_fc_m4_pass_deferred \
	"empty .fc file" \
	b3_empty_fc \
	"${OUTDIR}/empty.fc" \
	1

expect_fc_m4_pass_deferred \
	"path-only line without context in .fc" \
	b3_no_context \
	"${FIXTURES}/file_contexts/bad_no_context.fc"

expect_fc_m4_pass_deferred \
	"invalid regex metacharacters in .fc path" \
	b3_bad_regex \
	"${FIXTURES}/file_contexts/bad_regex.fc"

expect_fc_m4_fail \
	"missing .fc path" \
	b3_missing \
	"${OUTDIR}/does_not_exist.fc"

expect_fc_m4_fail \
	"directory instead of .fc file" \
	b3_directory \
	"${BASEDIR}"

expect_fc_m4_fail \
	"broken symlink for .fc" \
	b3_symlink \
	"${OUTDIR}/broken_symlink.fc"

expect_fc_m4_fail_unreadable

expect_fc_m4_fail \
	"broken M4 syntax in .fc" \
	b3_bad_m4 \
	"${FIXTURES}/file_contexts/bad_m4_syntax.fc"

# --- PDF #6.2: M4-expanded .mod.fc through semodule_package (E2E) ---
expect_m4_package_e2e_deferred \
	"bad M4-expanded .mod.fc packaged with good .mod (M4 to package E2E)" \
	b6_e2e \
	"${FIXTURES}/file_contexts/bad_context.fc" \
	"${GOOD_IF}" \
	"${FIXTURES}/modules/te_good.te"

echo "========================================"
echo "Results: ${PASS} passed, ${FAIL} failed"
if [ "${FAIL}" -ne 0 ]; then
	exit 1
fi
exit 0
