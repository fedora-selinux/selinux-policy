/*
 * Based off Example low-level D-Bus code.
 * Written by Matthew Johnson <dbus@matthew.ath.cx>
 *
 *
 */
#include <dbus/dbus.h>
extern DBusConnection *sedbus_receive(void func(), void *user_data);
extern int sedbus_send_avc(DBusConnection* conn, char *avc);
