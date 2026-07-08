# Minimal modular module build mirroring Rules.modular lines 73-86.
# Used by tests/bad-data/run.sh for PDF #1 Primary (missing .te at Makefile build).

POLICY_ROOT ?= ../../..
MODDIR ?=
OUTDIR ?= $(MODDIR)/out
MOD ?= bad_missing_te

M4 ?= m4
CHECKMODULE ?= checkmodule
CHECKMODULE_OPTS ?= -M -m
SEMOD_PKG ?= semodule_package
SED ?= sed

M4SUPPORT = $(POLICY_ROOT)/support/divert.m4 \
	$(POLICY_ROOT)/policy/support/misc_macros.spt \
	$(POLICY_ROOT)/policy/support/mls_mcs_macros.spt \
	$(POLICY_ROOT)/policy/support/loadable_module.spt \
	$(POLICY_ROOT)/policy/support/obj_perm_sets.spt \
	$(POLICY_ROOT)/support/undivert.m4

M4PARAM = -D enable_mcs -D distro_redhat -D hide_broken_symptoms \
	-D mls_num_sens=16 -D mls_num_cats=1024 -D mcs_num_cats=1024

IFERROR = $(POLICY_ROOT)/support/iferror.m4
EMPTY_GEN_DEF = /dev/null

$(OUTDIR)/generated_definitions.conf:
	@mkdir -p $(OUTDIR)
	@touch $@

$(OUTDIR)/all_interfaces.conf: $(M4SUPPORT) $(MODDIR)/$(MOD).if $(IFERROR)
	@mkdir -p $(OUTDIR)
	@echo 'divert(-1)' > $@
	$(M4) $(M4PARAM) $(M4SUPPORT) $(MODDIR)/$(MOD).if $(IFERROR) >> $(OUTDIR)/all_interfaces.tmp
	$(SED) -e 's/dollarsstar/$$*/g' $(OUTDIR)/all_interfaces.tmp >> $@
	@echo 'divert' >> $@

$(OUTDIR)/$(MOD).mod: $(M4SUPPORT) $(OUTDIR)/generated_definitions.conf \
		$(OUTDIR)/all_interfaces.conf $(MODDIR)/$(MOD).te
	@mkdir -p $(OUTDIR)
	$(M4) $(M4PARAM) -s $(M4SUPPORT) $(EMPTY_GEN_DEF) \
		$(OUTDIR)/all_interfaces.conf $(MODDIR)/$(MOD).te > $(OUTDIR)/$(MOD).tmp
	$(CHECKMODULE) $(CHECKMODULE_OPTS) -o $@ $(OUTDIR)/$(MOD).tmp

$(OUTDIR)/$(MOD).mod.fc: $(M4SUPPORT) $(MODDIR)/$(MOD).fc
	@mkdir -p $(OUTDIR)
	$(M4) $(M4PARAM) $(M4SUPPORT) $(MODDIR)/$(MOD).fc > $@

$(OUTDIR)/$(MOD).pp: $(OUTDIR)/$(MOD).mod $(OUTDIR)/$(MOD).mod.fc
	@mkdir -p $(OUTDIR)
	$(SEMOD_PKG) -o $@ -m $(OUTDIR)/$(MOD).mod -f $(OUTDIR)/$(MOD).mod.fc

.PHONY: all
all: $(OUTDIR)/$(MOD).pp
