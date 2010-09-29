/*
 * Copyright 2009 Red Hat Inc., Durham, North Carolina.
 * All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Authors:
 *   Dan Walsh <dwalsh@redhat.com>
 *
 * Based off Example low-level D-Bus code.
 * Written by Matthew Johnson <dbus@matthew.ath.cx>
 *
 */
#include <dbus/dbus.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static const char *PATH="/org/fedoraproject/Setroubleshootd";
static const char *BUSNAME="org.fedoraproject.Setroubleshootd";
static const char *INTERFACE="org.fedoraproject.SetroubleshootdIface";
static const char *NAME="alert";
static const char *RULE="type='signal',interface='org.fedoraproject.SetroubleshootdIface'";
static const char *ALERT="yellow";
static const char *REDALERT="red";

static void (*alert_func) (const void *user_data, int red, char *local_id);

static const char *
get_introspection_xml (void)
{
 	return "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n"
		"\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"
		"<node>\n"
		" <interface name=\"org.freedesktop.DBus.Introspectable\">\n"
		" <method name=\"Introspect\">\n"
		" <arg name=\"introspection_xml\" direction=\"out\" type=\"s\"/>\n"
		" </method>\n"
		" </interface>\n"
		"</node>\n";
} 

/* The content of this  function is copied in verbatim
 from dbus 0.20 file tools/dbus-print-message.c
 */
static DBusHandlerResult 
    _filter(DBusConnection *conn, DBusMessage *msg, void *data)
{
    const char *sender;
    int msg_type;
    DBusMessageIter args;
    DBusMessage *reply;
    char* sigvalue;

    msg_type = dbus_message_get_type (msg);
    sender = dbus_message_get_sender (msg); 
    
    if (dbus_message_is_method_call(msg,
				    "org.freedesktop.DBus.Introspectable",
				    "Introspect")) {
	    const char *introspection_xml;
	    introspection_xml = get_introspection_xml ();
	    
	    reply = dbus_message_new_method_return (msg);
	    dbus_message_append_args (reply, DBUS_TYPE_STRING, &introspection_xml,
				      DBUS_TYPE_INVALID);
	    
    } 

    if (dbus_message_is_signal(msg,                                 
			       INTERFACE, // interface name of the signal
			       NAME)) {
	    if (dbus_message_iter_init(msg, &args)) {
		    if (DBUS_TYPE_STRING == dbus_message_iter_get_arg_type(&args)) {
			    int redalert = FALSE;
			    dbus_message_iter_get_basic(&args, &sigvalue);
			    if (strcmp(sigvalue, REDALERT) == 0) {
				    redalert = TRUE;
			    }

			    if (dbus_message_iter_next(&args)) {
				    if (DBUS_TYPE_STRING == dbus_message_iter_get_arg_type(&args)) {
					    dbus_message_iter_get_basic(&args, &sigvalue);
				    }
			    }
			    alert_func(data, redalert, sigvalue);
			    return DBUS_HANDLER_RESULT_HANDLED;
		    }
	    }
    }
    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/**
 * Listens for signals on the bus
 */
int sedbus_send_avc(DBusConnection* conn, char *avc) {

	DBusMessage* msg;
	DBusMessageIter args;
	DBusPendingCall* pending;
	char* reply = NULL;

	msg = dbus_message_new_method_call(BUSNAME, 
					   PATH, 
					   INTERFACE,
					   "avc"); // method name
	if (NULL == msg) { 
		fprintf(stderr, "Can't communicate with setroubleshootd\n");
		return -1;
	}
	// append arguments
	dbus_message_iter_init_append(msg, &args);
	if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &avc)) { 
		fprintf(stderr, "Out Of Memory!\n"); 
		return -1;
	}

	// send message and get a handle for a reply
	if ( ! dbus_connection_send_with_reply (conn, msg, &pending, -1)) { 
		// -1 is default timeout
		fprintf(stderr, "Out Of Memory!\n"); 
		return -1;
	}
	if (NULL == pending) { 
		fprintf(stderr, "Pending Call Null\n"); 
		return -1;
	}
	dbus_connection_flush(conn);
	
	// free message
	dbus_message_unref(msg);

	// block until we receive a reply
	dbus_pending_call_block(pending);
   
	// get the reply message
	msg = dbus_pending_call_steal_reply(pending);
	if (NULL == msg) {
		fprintf(stderr, "Reply Null\n"); 
		exit(1); 
	}
	// free the pending message handle
	dbus_pending_call_unref(pending);

	// read the parameters
	if (!dbus_message_iter_init(msg, &args))
		fprintf(stderr, "Message has no arguments!\n"); 
	else if (DBUS_TYPE_STRING != dbus_message_iter_get_arg_type(&args)) 
		fprintf(stderr, "Argument is not boolean!\n"); 
	else
		dbus_message_iter_get_basic(&args, &reply);

	printf("Got Reply: %s\n", reply);

	// free reply and close connection
	dbus_message_unref(msg);   

	return 0;
}

DBusConnection *sedbus_receive(void func(), void *user_data)
{
   DBusConnection* conn;
   DBusError err;
   
   alert_func = func;

   // initialise the errors
   dbus_error_init(&err);
   
   // connect to the bus and check for errors
   conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
   if (dbus_error_is_set(&err)) { 
      fprintf(stderr, "Connection Error (%s)\n", err.message);
      dbus_error_free(&err); 
   }
   if (NULL == conn) { 
	   return NULL; 
   }
   
   // add a rule for which messages we want to see
   dbus_bus_add_match(conn, RULE, &err); // see signals from the given interface
   dbus_connection_flush(conn);
   if (dbus_error_is_set(&err)) { 
      fprintf(stderr, "Match Error (%s)\n", err.message);
      exit(1); 
   }

   if (!dbus_connection_add_filter(conn, _filter, user_data, NULL))
	   {
		   fprintf(stderr, "dbus_connection_add_filter failed");
		   return NULL; 
	   }

   return conn;
}

#ifdef DEBUG
/**
 * Connect to the DBUS bus and send a broadcast signal
 */
void sendsignal(char* sigvalue)
{
   DBusMessage* msg;
   DBusMessageIter args;
   DBusConnection* conn;
   DBusError err;
   int ret;
   dbus_uint32_t serial = 0;

   fprintf(stdout, "Sending signal with value %s\n", sigvalue);

   // initialise the error value
   dbus_error_init(&err);

   // connect to the DBUS system bus, and check for errors
   conn = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
   if (dbus_error_is_set(&err)) { 
      fprintf(stderr, "Connection Error (%s)\n", err.message); 
      dbus_error_free(&err); 
   }
   if (NULL == conn) { 
      exit(1); 
   }
   // create a signal & check for errors 
	msg = dbus_message_new_signal(PATH, // object name of the signal
                                 INTERFACE, // interface name of the signal
                                 NAME); // name of the signal
   if (NULL == msg) 
   { 
      fprintf(stderr, "Message Null\n"); 
      exit(1); 
   }

   // append arguments onto signal
   dbus_message_iter_init_append(msg, &args);
   if (!dbus_message_iter_append_basic(&args, DBUS_TYPE_STRING, &sigvalue)) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }

   // send the message and flush the connection
   if (!dbus_connection_send(conn, msg, &serial)) {
      fprintf(stderr, "Out Of Memory!\n"); 
      exit(1);
   }
   dbus_connection_flush(conn);
   
   fprintf(stdout, "Signal Sent\n");
   
   // free the message 
   dbus_message_unref(msg);
}

static void show_alert(char *test) {
	fprintf(stdout, "show alert %s\n", test);
}

static void receive()
{
	DBusConnection *conn = sedbus_receive(show_alert, "Test");
	// loop listening for messages being emmitted
	while (1) {
		// non blocking read of the next available message
		dbus_connection_read_write(conn, 0);
		while(dbus_connection_dispatch(conn) == DBUS_DISPATCH_DATA_REMAINS)
			;
		sleep(1);
	}
}

int main(int argc, char** argv)
{
   if (2 > argc) {
	   fprintf(stdout, "Syntax: %s [send|receive] [<param>]\n", argv[0] );
      return 1;
   }
   char* param = "no param";
   if (3 >= argc && NULL != argv[2]) param = argv[2];
   if (0 == strcmp(argv[1], "send"))
      sendsignal(param);
   else if (0 == strcmp(argv[1], "receive"))
      receive();
   else {
	   fprintf (stdout, "Syntax: dbus-example [send|receive|listen|query] [<param>]\n");
      return 1;
   }
   return 0;
}
#endif
