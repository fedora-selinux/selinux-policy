# Basic Makefile to allow building the SRPM automatically by COPR/CI

outdir ?= $(PWD)

srpm:
	$(dir $(lastword $(MAKEFILE_LIST)))/make-srpm.sh $(outdir)

.PHONY: srpm
