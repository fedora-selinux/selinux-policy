/**
 *  @file
 *  Command line tool to search TE rules.
 *
 *  @author Frank Mayer  mayerf@tresys.com
 *  @author Jeremy A. Mowery jmowery@tresys.com
 *  @author Paul Rosenfeld  prosenfeld@tresys.com
 *  @author Thomas Liu  <tliu@redhat.com>
 *
 *  Copyright (C) 2003-2008 Tresys Technology, LLC
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

/**
 * This is a modified version of sesearch to be used as part of a library for
 * Python bindings.
 */

#include "Python.h"

/* libapol */
#include <apol/policy.h>
#include <apol/policy-query.h>
#include <apol/render.h>
#include <apol/util.h>
#include <apol/vector.h>

/* libqpol*/
#include <qpol/policy.h>
#include <qpol/policy_extend.h>
#include <qpol/syn_rule_query.h>
#include <qpol/util.h>

/* other */
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <getopt.h>
#include <string.h>
#include <stdbool.h>

#define COPYRIGHT_INFO "Copyright (C) 2003-2007 Tresys Technology, LLC"
static char *policy_file = NULL;

enum opt_values
{
	RULE_NEVERALLOW = 256, RULE_AUDIT, RULE_AUDITALLOW, RULE_DONTAUDIT,
	RULE_ROLE_ALLOW, RULE_ROLE_TRANS, RULE_RANGE_TRANS, RULE_ALL,
	EXPR_ROLE_SOURCE, EXPR_ROLE_TARGET
};

;

typedef struct options
{
	char *src_name;
	char *tgt_name;
	char *src_role_name;
	char *tgt_role_name;
	char *class_name;
	char *permlist;
	char *bool_name;
	apol_vector_t *class_vector;
	bool all;
	bool lineno;
	bool semantic;
	bool indirect;
	bool allow;
	bool nallow;
	bool auditallow;
	bool dontaudit;
	bool type;
	bool rtrans;
	bool role_allow;
	bool role_trans;
	bool useregex;
	bool show_cond;
	apol_vector_t *perm_vector;
} options_t;

static int perform_av_query(const apol_policy_t * policy, const options_t * opt, apol_vector_t ** v)
{
	apol_avrule_query_t *avq = NULL;
	unsigned int rules = 0;
	int error = 0;
	char *tmp = NULL, *tok = NULL, *s = NULL;

	if (!policy || !opt || !v) {
		ERR(policy, "%s", strerror(EINVAL));
		errno = EINVAL;
		return -1;
	}

	if (!opt->all && !opt->allow && !opt->nallow && !opt->auditallow && !opt->dontaudit) {
		*v = NULL;
		return 0;	       /* no search to do */
	}

	avq = apol_avrule_query_create();
	if (!avq) {
		ERR(policy, "%s", strerror(ENOMEM));
		errno = ENOMEM;
		return -1;
	}

	if (opt->allow || opt->all)
		rules |= QPOL_RULE_ALLOW;
	if ((opt->nallow || opt->all) && qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_NEVERALLOW))
		rules |= QPOL_RULE_NEVERALLOW;
	if (opt->auditallow || opt->all)
		rules |= QPOL_RULE_AUDITALLOW;
	if (opt->dontaudit || opt->all)
		rules |= QPOL_RULE_DONTAUDIT;
	apol_avrule_query_set_rules(policy, avq, rules);
	apol_avrule_query_set_regex(policy, avq, opt->useregex);
	if (opt->src_name)
		apol_avrule_query_set_source(policy, avq, opt->src_name, opt->indirect);
	if (opt->tgt_name)
		apol_avrule_query_set_target(policy, avq, opt->tgt_name, opt->indirect);
	if (opt->bool_name)
		apol_avrule_query_set_bool(policy, avq, opt->bool_name);
	if (opt->class_name) {
		if (opt->class_vector == NULL) {
			if (apol_avrule_query_append_class(policy, avq, opt->class_name)) {
				error = errno;
				goto err;
			}
		} else {
			size_t i;
            for (i = 0; i < apol_vector_get_size(opt->class_vector); ++i) {
				char *class_name;
				class_name = apol_vector_get_element(opt->class_vector, i);
				if (!class_name)
					continue;
				if (apol_avrule_query_append_class(policy, avq, class_name)) {
					error = errno;
					goto err;
				}
			}
		}
	}

	if (opt->permlist) {
		tmp = strdup(opt->permlist);
		for (tok = strtok(tmp, ","); tok; tok = strtok(NULL, ",")) {
			if (apol_avrule_query_append_perm(policy, avq, tok)) {
				error = errno;
				goto err;
			}
			if ((s = strdup(tok)) == NULL || apol_vector_append(opt->perm_vector, s) < 0) {
				error = errno;
				goto err;
			}
			s = NULL;
		}
		free(tmp);
	}

	if (!(opt->semantic) && qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_SYN_RULES)) {
		if (apol_syn_avrule_get_by_query(policy, avq, v)) {
			error = errno;
			goto err;
		}
	} else {
		if (apol_avrule_get_by_query(policy, avq, v)) {
			error = errno;
			goto err;
		}
	}

	apol_avrule_query_destroy(&avq);
	return 0;

      err:
	apol_vector_destroy(v);
	apol_avrule_query_destroy(&avq);
	free(tmp);
	free(s);
	ERR(policy, "%s", strerror(error));
	errno = error;
	return -1;
}



static PyObject* print_av_results(const apol_policy_t * policy, const options_t * opt, const apol_vector_t * v)
{
    PyObject *list = PyList_New(0);
	qpol_policy_t *q = apol_policy_get_qpol(policy);
	size_t i, num_rules = 0;
	const qpol_avrule_t *rule = NULL;
	char *tmp = NULL, *rule_str = NULL, *expr = NULL;
	char enable_char = ' ', branch_char = ' ';
	qpol_iterator_t *iter = NULL;
	uint32_t enabled = 0;

	if (!policy || !v)
		return 0;

	if (!(num_rules = apol_vector_get_size(v)))
		return 0;




	for (i = 0; i < num_rules; i++) {
		enable_char = branch_char = ' ';
		if (!(rule = apol_vector_get_element(v, i)))
			goto cleanup;
		
        if (qpol_avrule_get_is_enabled(q, rule, &enabled))
            goto cleanup;
        if (!enabled)
            continue;
		
        
        
        const qpol_type_t *type;
        const char *tmp_name;
        uint32_t rule_type = 0;
       
	    const qpol_class_t *obj_class = NULL;

        PyObject *dict = PyDict_New(); 

        qpol_avrule_get_rule_type(q, rule, &rule_type);
        tmp_name = apol_rule_type_to_str(rule_type);
        PyDict_SetItemString(dict, "type", PyString_FromString(tmp_name));
        // source
        qpol_avrule_get_source_type(q, rule, &type);
        qpol_type_get_name(q, type, &tmp_name);
        PyDict_SetItemString(dict, "scontext", PyString_FromString(tmp_name));
        
        qpol_avrule_get_target_type(q, rule, &type);
        qpol_type_get_name(q, type, &tmp_name);
        PyDict_SetItemString(dict, "tcontext", PyString_FromString(tmp_name));
        
        qpol_avrule_get_object_class(q, rule, &obj_class);
        qpol_type_get_name(q, type, &tmp_name);
        PyDict_SetItemString(dict, "class", PyString_FromString(tmp_name));
        qpol_avrule_get_perm_iter(q, rule, &iter);
        PyObject *permlist = PyList_New(0);
        for (; !qpol_iterator_end(iter); qpol_iterator_next(iter)) {
            const char *perm_name = NULL;
            qpol_iterator_get_item(iter, (void **)&perm_name);
            PyList_Append(permlist, PyString_FromString(perm_name));
        }
        PyDict_SetItemString(dict, "permlist", permlist);
        PyList_Append(list, dict); 


        free(rule_str);
		rule_str = NULL;
		free(expr);
		expr = NULL;
	}
      cleanup:
	free(tmp);
	free(rule_str);
	free(expr);
    return list;
}


PyObject* sesearch(bool allow,
             bool neverallow, 
             bool auditallow,
             bool dontaudit,
             const char *src_name,
             const char *tgt_name,
             const char *class_name,
             const char *permlist
             )
{
	options_t cmd_opts;
	int rt = -1;

	apol_policy_t *policy = NULL;
	apol_vector_t *v = NULL;
	apol_policy_path_t *pol_path = NULL;
	apol_vector_t *mod_paths = NULL;
	apol_policy_path_type_e path_type = APOL_POLICY_PATH_TYPE_MONOLITHIC;

	memset(&cmd_opts, 0, sizeof(cmd_opts));
	cmd_opts.indirect = true;
    cmd_opts.allow = allow;
    cmd_opts.nallow = neverallow;
    cmd_opts.auditallow = auditallow;
    cmd_opts.dontaudit = dontaudit;
    if (src_name)
        cmd_opts.src_name = strdup(src_name);
    if (tgt_name)
        cmd_opts.tgt_name = strdup(tgt_name);
    if (class_name)
        cmd_opts.class_name = strdup(class_name);
    if (permlist){
        cmd_opts.perm_vector = apol_vector_create(free);
        cmd_opts.permlist = strdup(permlist);
    }
    int pol_opt = 0;
	if (!(cmd_opts.nallow || cmd_opts.all))
		pol_opt |= QPOL_POLICY_OPTION_NO_NEVERALLOWS;

    
    rt = qpol_default_policy_find(&policy_file);
    if (rt < 0) {
        fprintf(stderr, "Default policy search failed: %s\n", strerror(errno));
        exit(1);
    } else if (rt != 0) {
        fprintf(stderr, "No default policy found.\n");
        exit(1);
    }
    pol_opt |= QPOL_POLICY_OPTION_MATCH_SYSTEM;

	if (apol_file_is_policy_path_list(policy_file) > 0) {
		pol_path = apol_policy_path_create_from_file(policy_file);
		if (!pol_path) {
			ERR(policy, "%s", "invalid policy list");
			free(policy_file);
			exit(1);
		}
	}

	if (!pol_path)
		pol_path = apol_policy_path_create(path_type, policy_file, mod_paths);
	if (!pol_path) {
		ERR(policy, "%s", strerror(ENOMEM));
		free(policy_file);
		apol_vector_destroy(&mod_paths);
		exit(1);
	}
	free(policy_file);
	apol_vector_destroy(&mod_paths);

	policy = apol_policy_create_from_policy_path(pol_path, pol_opt, NULL, NULL);
	if (!policy) {
		ERR(policy, "%s", strerror(errno));
		apol_policy_path_destroy(&pol_path);
		exit(1);
	}
	/* handle regex for class name */
	if (cmd_opts.useregex && cmd_opts.class_name != NULL) {
		cmd_opts.class_vector = apol_vector_create(NULL);
		apol_vector_t *qpol_matching_classes = NULL;
		apol_class_query_t *regex_match_query = apol_class_query_create();
		apol_class_query_set_regex(policy, regex_match_query, 1);
		apol_class_query_set_class(policy, regex_match_query, cmd_opts.class_name);
		if (apol_class_get_by_query(policy, regex_match_query, &qpol_matching_classes)) {
			apol_class_query_destroy(&regex_match_query);
			goto cleanup;
		}
		const qpol_class_t *class = NULL;
		size_t i;
        for (i = 0; i < apol_vector_get_size(qpol_matching_classes); ++i) {
			const char *class_name;
			class = apol_vector_get_element(qpol_matching_classes, i);
			if (!class)
				break;
			qpol_class_get_name(apol_policy_get_qpol(policy), class, &class_name);
			apol_vector_append(cmd_opts.class_vector, (void *)class_name);
		}
		if (!apol_vector_get_size(qpol_matching_classes)) {
			apol_vector_destroy(&qpol_matching_classes);
			apol_class_query_destroy(&regex_match_query);
			ERR(policy, "No classes match expression %s", cmd_opts.class_name);
			goto cleanup;
		}
		apol_vector_destroy(&qpol_matching_classes);
		apol_class_query_destroy(&regex_match_query);
	}

	if (!cmd_opts.semantic && qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_SYN_RULES)) {
		if (qpol_policy_build_syn_rule_table(apol_policy_get_qpol(policy))) {
			apol_policy_destroy(&policy);
			exit(1);
		}
	}

	/* if syntactic rules are not available always do semantic search */
	if (!qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_SYN_RULES)) {
		cmd_opts.semantic = 1;
	}

	/* supress line numbers if doing semantic search or not available */
	if (cmd_opts.semantic || !qpol_policy_has_capability(apol_policy_get_qpol(policy), QPOL_CAP_LINE_NUMBERS)) {
		cmd_opts.lineno = 0;
	}
    PyObject *output = NULL;
	if (perform_av_query(policy, &cmd_opts, &v)) {
		rt = 1;
		goto cleanup;
	}
	if (v) {
        output =  print_av_results(policy, &cmd_opts, v);
	}
	apol_vector_destroy(&v);
		rt = 0;
      cleanup:
	apol_policy_destroy(&policy);
	apol_policy_path_destroy(&pol_path);
	free(cmd_opts.src_name);
	free(cmd_opts.tgt_name);
	free(cmd_opts.class_name);
	free(cmd_opts.permlist);
	free(cmd_opts.bool_name);
	free(cmd_opts.src_role_name);
	free(cmd_opts.tgt_role_name);
	apol_vector_destroy(&cmd_opts.perm_vector);
	apol_vector_destroy(&cmd_opts.class_vector);
	
    return output;
}

