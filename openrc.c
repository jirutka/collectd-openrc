// SPDX-FileCopyrightText: 2022-present Jakub Jirutka <jakub@jirutka.cz>
// SPDX-License-Identifier: GPL-2.0-or-later

#include <assert.h>
#include <errno.h>
#include <math.h>
#include <stddef.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <json.h>  // json-c
#include <rc.h>  // openrc
#include <daemon/plugin.h>  // collectd

#define PLUGIN_NAME "openrc"

#ifndef PLUGIN_VERSION
  #define PLUGIN_VERSION "0.2.0"
#endif

#define TRUE 1
#define FALSE 0
#define ERR -1

#define LOG_PREFIX PLUGIN_NAME " plugin: "

#ifndef STATIC_ARRAY_SIZE
  // Copied from src/utils/common/common.h in colllectd.
  #define STATIC_ARRAY_SIZE(a) (sizeof(a) / sizeof(*(a)))
#endif

// Based on src/shared/queue.h in OpenRC.
#define	tailq_foreach(var, head) \
	for ((var) = ((head) ? (head)->tqh_first : NULL); \
	     (var) != NULL; \
	     (var) = ((var)->entries.tqe_next))

// LOG_DEBUG only works if collectd was compiled with --enable-debug (disabled
// by default), which makes it quite useless. The first usable log level is
// LOG_INFO, which is however enabled by default for logging into syslog and
// file. For this reason, this plugin allows to override the logging level for
// itself using the plugin parameter "LogLevel" and sets it to LOG_NOTICE by
// default.
#define openrc_plugin_log(level, ...) \
	if (level <= log_level) { plugin_log(level, LOG_PREFIX __VA_ARGS__); }

#define log_info(...) openrc_plugin_log(LOG_INFO, __VA_ARGS__)
#define log_notice(...) openrc_plugin_log(LOG_NOTICE, __VA_ARGS__)
#define log_warn(...) openrc_plugin_log(LOG_WARNING, __VA_ARGS__)
#define log_err(...) openrc_plugin_log(LOG_ERR, __VA_ARGS__)


static const char *config_keys[] = {
	"LogLevel",  // the logging level for this plugin
};

static data_set_t services_ds = {
	.type = "services",
	.ds = &(data_source_t){
		.name = "value",
		.type = DS_TYPE_GAUGE,
		.min = 0.0,
		.max = NAN,
	},
	.ds_num = 1,
};

static int log_level = LOG_NOTICE;

static int dispatch_gauge (const char *type, const char *type_instance,
                           const gauge_t value, meta_data_t *meta) {
	value_list_t vl = {
		.plugin = PLUGIN_NAME,
		.values = &(value_t){ .gauge = value },
		.values_len = 1,
		.meta = meta,
	};
	strncpy(vl.type, type, sizeof(vl.type));
	strncpy(vl.type_instance, type_instance, sizeof(vl.type_instance));

	const int status = plugin_dispatch_values(&vl);
	meta_data_destroy(meta);

	return status;
}

// We intend to provide more information about services in the future.
static json_object *service_to_json (const char *service) {
	json_object *obj = json_object_new_object();
	json_object_object_add(obj, "n", json_object_new_string(service));

	return obj;
}

// Based on code in rc_service_daemons_crashed.
static void pidlist_free (RC_PIDLIST *head) {
	if (head == NULL) {
		return;
	}
	RC_PID *p1 = head->lh_first;
	RC_PID *p2;

	while (p1) {
		p2 = p1->entries.le_next;
		free(p1);
		p1 = p2;
	}
	free(head);
}

static int service_daemons_crashed (const char *service) {
	int status = FALSE;
	char *pidfile = NULL;
	char *command = NULL;
	RC_PIDLIST *pids = NULL;

	errno = 0;
	if (!rc_service_daemons_crashed(service)) {
		status = FALSE;
		goto done;
	}
	if (errno != EACCES && errno != ESRCH) {
		log_err("unable to check status of service '%s': %s", service, strerror(errno));
		status = ERR;
		goto done;
	}

	// When collectd runs under an unprivileged user (which is strongly
	// recommended), it may not have access to the service pidfile and
	// `rc_service_daemons_crashed` reports it as crashed (the same as
	// `rc-status --crashed`). The following code tries to somehow workaround
	// this issue, at least for some init scripts. If the init script redefines
	// the start function and doesn't set the command option (using
	// `service_set_value`), there's nothing we can do.

	if ((pidfile = rc_service_value_get(service, "pidfile")) == NULL) {
		log_info("service '%s' has no pidfile option defined", service);
		status = TRUE;
		goto done;
	}

	errno = 0;
	if (access(pidfile, R_OK) && errno != EACCES) {
		log_err("unable to check status of service '%s' due to EACCES, but pidfile is "
		        "readable", service);
		status = ERR;
		goto done;
	}

	if ((command = rc_service_value_get(service, "command")) == NULL) {
		log_notice("unable to determine status of service '%s': collectd user (%d) "
		           "does not have permissions to read pidfile '%s' and 'command' "
		           "option is not defined (the init script should be fixed)",
		           service, geteuid(), pidfile);
		status = FALSE;
		goto done;
	}

	if ((pids = rc_find_pids(command, NULL, 0, 0)) == NULL) {
		log_info("unable to read pidfile '%s' and no process with exec '%s' found",
		          pidfile, command);
		status = TRUE;
		goto done;
	}

	log_info("unable to read pidfile '%s' of service '%s', but found a process based on "
	         "exec '%s'", pidfile, service, command);
	status = FALSE;

done:
	pidlist_free(pids);
	free(command);
	free(pidfile);

	return status;
}

static bool is_service_in_any_runlevel (const char *service, const RC_STRINGLIST *runlevels) {
	RC_STRING *runlevel = NULL;

	tailq_foreach(runlevel, runlevels) {
		if (rc_service_in_runlevel(service, runlevel->value)) {
			return true;
		}
	}
	return false;
}

static json_object *collect_services_status (void) {
	json_object *data = json_object_new_object();

	json_object *started = json_object_new_array();
	json_object_object_add(data, "started", started);

	json_object *crashed = json_object_new_array();
	json_object_object_add(data, "crashed", crashed);

	json_object *stopped = json_object_new_array();
	json_object_object_add(data, "stopped", stopped);

	RC_STRINGLIST *runlevels = rc_runlevel_list();
	rc_stringlist_delete(runlevels, "shutdown");

	RC_STRING *str = NULL;
	RC_STRINGLIST *services = rc_services_in_runlevel(NULL);  // get all services

	tailq_foreach(str, services) {
		const char *service = str->value;
		const RC_SERVICE state = rc_service_state(service);

		json_object *entry = service_to_json(service);

		// only supervised services can be FAILED (?)
		if (state & RC_SERVICE_FAILED) {
			json_object_array_add(crashed, entry);

		} else if (state & RC_SERVICE_STARTED) {
			switch (service_daemons_crashed(service)) {
				case ERR:
					json_object_put(entry);  // free
					goto error;
				// supervised services cannot be CRASHED, only FAILED
				case TRUE:
					json_object_array_add(crashed, entry);
					break;
				case FALSE:
					json_object_array_add(started, entry);
			}
		} else if ((state & RC_SERVICE_STOPPED) \
		           && is_service_in_any_runlevel(service, runlevels)) {
			json_object_array_add(stopped, entry);

		} else {
			json_object_put(entry);  // free
		}
	}
	goto done;

error:
	json_object_put(data);  // free
	data = NULL;
done:
	rc_stringlist_free(services);
	rc_stringlist_free(runlevels);

	return data;
}

static int openrc_read (void) {
	int rc = 0;
	json_object *data = NULL;

	if (!(data = collect_services_status())) {
		goto error;
	}

	json_object_object_foreach(data, key, value) {
		const char *services = json_object_to_json_string_ext(value, JSON_C_TO_STRING_PLAIN);
		int count = json_object_array_length(value);

		log_info("%s services = %s", key, services);

		meta_data_t *meta = meta_data_create();
		if (meta_data_add_string(meta, "services", services) < 0) {
			log_err("unable to set value metadata");
			meta_data_destroy(meta);
			goto error;
		}

		dispatch_gauge("services", key, count, meta);
	}
	goto done;

error:
	rc = ERR;
done:
	json_object_put(data);  // free

	return rc;
}

static int openrc_config (const char *key, const char *value) {
	if (strcasecmp(key, "LogLevel") == 0) {
		log_level = parse_log_severity(value);
		if (log_level < 0) {
			log_level = LOG_NOTICE;
			log_warn("invalid LogLevel '%s', defaulting to 'notice'", value);
		}
	}
	return 0;
}

// cppcheck-suppress unusedFunction
void module_register (void) {
	INFO("registering plugin " PLUGIN_NAME " " PLUGIN_VERSION);

	plugin_register_config(PLUGIN_NAME, openrc_config, config_keys,
	                       STATIC_ARRAY_SIZE(config_keys));
	plugin_register_data_set(&services_ds);
	plugin_register_read(PLUGIN_NAME, openrc_read);
}
