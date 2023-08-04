# Basic Makefile to allow building the SRPM automatically by COPR/CI

outdir ?= $(PWD)

COPR_DIR := $(dir $(lastword $(MAKEFILE_LIST)))

srpm:
	$(COPR_DIR)/../scripts/make-srpm.sh $(outdir)

.PHONY: srpm
