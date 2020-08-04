#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h> /* for glib main loop */
#include "sgx_eid.h"
#include "sgx_urts.h"
#include "Enclave_u.h" //Gerado pelo Edger8r

#define ENCLAVE_FILENAME "/lib/x86_64-linux-gnu/security/enclave.signed.so"
# define SEALED_SHADOW "/home/newton/unisgx/sealed_shadow"

DBusHandlerResult server_get_properties_handler(const char *property, DBusConnection *conn, DBusMessage *reply);
DBusHandlerResult server_get_all_properties_handler(DBusConnection *conn, DBusMessage *reply);
DBusHandlerResult server_message_handler(DBusConnection *conn, DBusMessage *message, void *data);
sgx_status_t create_enclave(void);
sgx_status_t load_shadow(void);
sgx_status_t init_enclave(void);
sgx_status_t verify_user_pwd(sgx_enclave_id_t enclave_id, sgx_aes_gcm_data_t* message, size_t message_size, sgx_aes_gcm_data_t* response, size_t response_size);
sgx_status_t session_request(sgx_enclave_id_t enclave_id, sgx_dh_msg1_t *dh_msg1);
sgx_status_t exchange_report(sgx_enclave_id_t enclave_id, sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, sgx_key_128bit_t *dh_aek);

const char *version = "0.1";
const char *iface = "br.ufpr.inf.larsis.UniSGXInterface";
const char *serverName = "br.ufpr.inf.larsis.UniSGX";
const char *objectPath = "/br/ufpr/inf/larsis/Object";
GMainLoop *mainloop;
sgx_enclave_id_t eid = 0;
pthread_mutex_t lock;

const DBusObjectPathVTable server_vtable = {
	.message_function = server_message_handler
};

const char *server_introspection_xml =
	DBUS_INTROSPECT_1_0_XML_DOCTYPE_DECL_NODE
	"<node>\n"

	"  <interface name='org.freedesktop.DBus.Introspectable'>\n"
	"    <method name='Introspect'>\n"
	"      <arg name='data' type='s' direction='out' />\n"
	"    </method>\n"
	"  </interface>\n"

	"  <interface name='org.freedesktop.DBus.Properties'>\n"
	"    <method name='Get'>\n"
	"      <arg name='interface' type='s' direction='in' />\n"
	"      <arg name='property'  type='s' direction='in' />\n"
	"      <arg name='value'     type='s' direction='out' />\n"
	"    </method>\n"
	"    <method name='GetAll'>\n"
	"      <arg name='interface'  type='s'     direction='in'/>\n"
	"      <arg name='properties' type='a{sv}' direction='out'/>\n"
	"    </method>\n"
	"  </interface>\n"

	"  <interface name='br.ufpr.inf.larsis.UniSGXInterface'>\n"
	"    <property name='Version' type='s' access='read' />\n"
	"    <method name='verify_password'>\n"
	"      <arg name='enclave_id' direction='in' type='t'/>\n"
	"      <arg name='data' direction='in' type='a'/>\n"
	"      <arg type='y' direction='out' />\n"
	"      <arg type='a' direction='out' />\n"
	"    </method>\n"
	"    <method name='session_request'>\n"
	"      <arg name='enclave_id' direction='in' type='t'/>\n"
	"      <arg type='a' direction='out' />\n"
	"    </method>\n"
	"    <method name='exchange_report'>\n"
	"      <arg name='enclave_id' direction='in' type='t'/>\n"
	"      <arg name='data' direction='in' type='a'/>\n"
	"      <arg type='a' direction='out' />\n"
	"      <arg type='a' direction='out' />\n"
	"    </method>\n"
	"    <method name='Ping' >\n"
	"      <arg type='s' direction='out' />\n"
	"    </method>\n"
	"    <method name='Echo'>\n"
	"      <arg name='string' direction='in' type='s'/>\n"
	"      <arg type='s' direction='out' />\n"
	"    </method>\n"
	"    <method name='EmitSignal'>\n"
	"    </method>\n"
	"    <method name='Quit'>\n"
	"    </method>\n"
	"    <signal name='OnEmitSignal'>\n"
	"    </signal>"
	"  </interface>\n"

	"</node>\n";

int main(void) {
	DBusConnection *conn;
	DBusError err;
	int rv;

	pthread_mutex_init(&lock, NULL);

	init_enclave();

	dbus_error_init(&err);

	/* connect to the daemon bus */
	conn = dbus_bus_get(DBUS_BUS_SESSION, &err);
	if (!conn) {
		fprintf(stderr, "Failed to get a session DBus connection: %s\n", err.message);
		goto fail;
	}

	rv = dbus_bus_request_name(conn, serverName, DBUS_NAME_FLAG_REPLACE_EXISTING , &err);
	if (rv != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		fprintf(stderr, "Failed to request name on bus: %s\n", err.message);
		goto fail;
	}

	if (!dbus_connection_register_object_path(conn, objectPath, &server_vtable, NULL)) {
		fprintf(stderr, "Failed to register a object path for 'TestObject'\n");
		goto fail;
	}

	/*
	 * For the sake of simplicity we're using glib event loop to
	 * handle DBus messages. This is the only place where glib is
	 * used.
	 */
	printf("Starting UniSGX Server v%s\n", version);
	mainloop = g_main_loop_new(NULL, false);
	/* Set up the DBus connection to work in a GLib event loop */
	dbus_connection_setup_with_g_main(conn, NULL);
	/* Start the glib event loop */
	g_main_loop_run(mainloop);

	return EXIT_SUCCESS;
fail:
	dbus_error_free(&err);
	return EXIT_FAILURE;
}

/*
 * This implements 'Get' method of DBUS_INTERFACE_PROPERTIES so a
 * client can inspect the properties/attributes of 'TestInterface'.
 */
DBusHandlerResult server_get_properties_handler(const char *property, DBusConnection *conn, DBusMessage *reply) {
	if (!strcmp(property, "Version")) {
		dbus_message_append_args(reply,
					 DBUS_TYPE_STRING, &version,
					 DBUS_TYPE_INVALID);
	} else
		/* Unknown property */
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (!dbus_connection_send(conn, reply, NULL))
		return DBUS_HANDLER_RESULT_NEED_MEMORY;
	return DBUS_HANDLER_RESULT_HANDLED;
}

/*
 * This implements 'GetAll' method of DBUS_INTERFACE_PROPERTIES. This
 * one seems required by g_dbus_proxy_get_cached_property().
 */
DBusHandlerResult server_get_all_properties_handler(DBusConnection *conn, DBusMessage *reply) {
	DBusHandlerResult result;
	DBusMessageIter array, dict, iter, variant;
	const char *property = "Version";

	/*
	 * All dbus functions used below might fail due to out of
	 * memory error. If one of them fails, we assume that all
	 * following functions will fail too, including
	 * dbus_connection_send().
	 */
	result = DBUS_HANDLER_RESULT_NEED_MEMORY;

	dbus_message_iter_init_append(reply, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &array);

	/* Append all properties name/value pairs */
	property = "Version";
	dbus_message_iter_open_container(&array, DBUS_TYPE_DICT_ENTRY, NULL, &dict);
	dbus_message_iter_append_basic(&dict, DBUS_TYPE_STRING, &property);
	dbus_message_iter_open_container(&dict, DBUS_TYPE_VARIANT, "s", &variant);
	dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &version);
	dbus_message_iter_close_container(&dict, &variant);
	dbus_message_iter_close_container(&array, &dict);

	dbus_message_iter_close_container(&iter, &array);

	if (dbus_connection_send(conn, reply, NULL))
		result = DBUS_HANDLER_RESULT_HANDLED;

	return result;
}

/*
 * This function implements the 'TestInterface' interface for the
 * 'Server' DBus object.
 *
 * It also implements 'Introspect' method of
 * 'org.freedesktop.DBus.Introspectable' interface which returns the
 * XML string describing the interfaces, methods, and signals
 * implemented by 'Server' object. This also can be used by tools such
 * as d-feet(1) and can be queried by:
 *
 * $ gdbus introspect --session --dest org.example.TestServer --object-path /org/example/TestObject
 */
DBusHandlerResult server_message_handler(DBusConnection *conn, DBusMessage *message, void *data) {
	DBusHandlerResult result;
    	DBusMessage *reply = NULL;
	DBusError err;
	bool quit = false;
	sgx_enclave_id_t enclave_id;

	// fprintf(stderr, "Got D-Bus request: %s.%s on %s\n", dbus_message_get_interface(message), dbus_message_get_member(message), dbus_message_get_path(message));

	/*
	 * Does not allocate any memory; the error only needs to be
	 * freed if it is set at some point.
	 */
	dbus_error_init(&err);

	if (dbus_message_is_method_call(message, iface, "verify_password")) {
		//pthread_mutex_lock(&lock);

		sgx_aes_gcm_data_t* msg;
		char *pReadData;
		int len, error = 0;
		sgx_aes_gcm_data_t* response;
		size_t response_size = sizeof(sgx_aes_gcm_data_t) + 3;

		//fprintf(stderr, "Starting verify_password\n");

		if (!dbus_message_get_args(message, &err, DBUS_TYPE_UINT64, &enclave_id, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &pReadData, &len, DBUS_TYPE_INVALID)) {
			error = 11;
		}

		//fprintf(stderr, "Parameters OK\n");
		//fprintf(stderr, "Name: %s; Pass: %s\n", name, password);

		//if(error == 0) {
		//	if(init_enclave() == SGX_SUCCESS) {
		//		error = 3;
		//	}
		//}

		msg = (sgx_aes_gcm_data_t*)malloc(len);
		memcpy(msg, pReadData, len);

		//fprintf(stderr, "Enclave loaded\n");

		response = (sgx_aes_gcm_data_t*)malloc(response_size);
		response->payload_size = 3;

		if(error == 0) {
			error = verify_user_pwd(enclave_id, msg, len, response, response_size);
		}

		//fprintf(stderr, "verify_user_pwd response %d\n", error);

		if (!(reply = dbus_message_new_method_return(message))) {
			goto fail;
		}

		dbus_message_append_args(reply, DBUS_TYPE_BYTE, &error, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &response, response_size, DBUS_TYPE_INVALID);

		//free(pReadData);
		//free(msg);

		// printf("Sender: %s\n", dbus_message_get_sender(message));

		//dbus_message_set_destination(reply, dbus_message_get_sender(message));

		//pthread_mutex_unlock(&lock);

	} else if (dbus_message_is_method_call(message, iface, "session_request")) {
		//pthread_mutex_lock(&lock);

		unsigned char response = 0;
		sgx_dh_msg1_t *dh_msg1 = malloc(sizeof(sgx_dh_msg1_t));

		//printf("D-BUS session_request\n");

		if (!dbus_message_get_args(message, &err, DBUS_TYPE_UINT64, &enclave_id, DBUS_TYPE_INVALID)) {
			printf("session_request ERROR\n");
			quit = true;
			response = 11;
		}

		//printf("session_request ARGS OK\n");

		//if(init_enclave() == SGX_SUCCESS) {
		//	response = 3;
		//}

		//printf("Enclave criado %ld\n", eid);

		if (session_request(enclave_id, dh_msg1) == 0) {
			//printf("D-BUS session_request OK\n");

			if (!(reply = dbus_message_new_method_return(message))) {
				goto fail;
			}

			dbus_message_append_args(reply, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &dh_msg1, sizeof(sgx_dh_msg1_t), DBUS_TYPE_INVALID);

			//printf("%s\n", dh_msg1);
		}

		//pthread_mutex_unlock(&lock);

	} else if (dbus_message_is_method_call(message, iface, "exchange_report")) {
		//pthread_mutex_lock(&lock);

		unsigned char response = 0;
		sgx_dh_msg2_t dh_msg2;
		sgx_dh_msg3_t *dh_msg3 = malloc(sizeof(sgx_dh_msg3_t));
		sgx_key_128bit_t *dh_aek = malloc(sizeof(sgx_key_128bit_t));
		char *pReadData;
		int len;

		if (!dbus_message_get_args(message, &err, DBUS_TYPE_UINT64, &enclave_id, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &pReadData, &len, DBUS_TYPE_INVALID)) {
			response = 11;
		}

		memcpy(&dh_msg2, pReadData, len);

		//if(response == 0) {
		//	if(init_enclave() == SGX_SUCCESS) {
		//		response = 3;
		//	}
		//}

		if (exchange_report(enclave_id, &dh_msg2, dh_msg3, dh_aek) == 0) {
			if (!(reply = dbus_message_new_method_return(message))) {
				goto fail;
			}

			dbus_message_append_args(reply, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &dh_msg3, sizeof(sgx_dh_msg3_t), DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &dh_aek, sizeof(sgx_key_128bit_t), DBUS_TYPE_INVALID);
		}

		//pthread_mutex_unlock(&lock);

	} else if (dbus_message_is_method_call(message, DBUS_INTERFACE_INTROSPECTABLE, "Introspect")) {
		if (!(reply = dbus_message_new_method_return(message)))
			goto fail;

		dbus_message_append_args(reply,
					 DBUS_TYPE_STRING, &server_introspection_xml,
					 DBUS_TYPE_INVALID);

	} else if (dbus_message_is_method_call(message, DBUS_INTERFACE_PROPERTIES, "Get")) {
		const char *interface, *property;

		if (!dbus_message_get_args(message, &err,
					   DBUS_TYPE_STRING, &interface,
					   DBUS_TYPE_STRING, &property,
					   DBUS_TYPE_INVALID))
			goto fail;

		if (!(reply = dbus_message_new_method_return(message)))
			goto fail;

		result = server_get_properties_handler(property, conn, reply);
		dbus_message_unref(reply);
		return result;

	} else if (dbus_message_is_method_call(message, DBUS_INTERFACE_PROPERTIES, "GetAll")) {
		if (!(reply = dbus_message_new_method_return(message)))
			goto fail;

		result = server_get_all_properties_handler(conn, reply);
		dbus_message_unref(reply);
		return result;

	}  else if (dbus_message_is_method_call(message, iface, "Ping")) {
		const char *pong = "Pong";

		if (!(reply = dbus_message_new_method_return(message)))
			goto fail;

		dbus_message_append_args(reply,
					 DBUS_TYPE_STRING, &pong,
					 DBUS_TYPE_INVALID);

	} else if (dbus_message_is_method_call(message, iface, "Echo")) {
		const char *msg;

		if (!dbus_message_get_args(message, &err,
					   DBUS_TYPE_STRING, &msg,
					   DBUS_TYPE_INVALID))
			goto fail;

		if (!(reply = dbus_message_new_method_return(message)))
			goto fail;

		dbus_message_append_args(reply,
					 DBUS_TYPE_STRING, &msg,
					 DBUS_TYPE_INVALID);
	} else if (dbus_message_is_method_call(message, iface, "Quit")) {
		/*
		 * Quit() has no return values but a METHOD_RETURN
		 * reply is required, so the caller will know the
		 * method was successfully processed.
		 */
		reply = dbus_message_new_method_return(message);
		quit  = true;

	} else
		return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

fail:
	if (dbus_error_is_set(&err)) {
		if (reply)
			dbus_message_unref(reply);
		reply = dbus_message_new_error(message, err.name, err.message);
		dbus_error_free(&err);
	}

	/*
	 * In any cases we should have allocated a reply otherwise it
	 * means that we failed to allocate one.
	 */
	if (!reply)
		return DBUS_HANDLER_RESULT_NEED_MEMORY;

	/* Send the reply which might be an error one too. */
	result = DBUS_HANDLER_RESULT_HANDLED;
	if (!dbus_connection_send(conn, reply, NULL))
		result = DBUS_HANDLER_RESULT_NEED_MEMORY;
	dbus_message_unref(reply);

	if (quit) {
		fprintf(stderr, "Server exiting...\n");
		g_main_loop_quit(mainloop);		

		if(eid != 0)
			sgx_destroy_enclave(eid);
	}

	return result;
}

sgx_status_t init_enclave(void) {
	sgx_status_t ret;

	//pthread_mutex_lock(&lock);

	if(eid == 0) {
		//fprintf(stderr, "Criando enclave\n");

		ret = create_enclave();

		if(ret == SGX_SUCCESS) {
			ret = load_shadow();
		}
	}

	//pthread_mutex_unlock(&lock);

	return ret;
}

sgx_status_t create_enclave(void) {
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;
	int updated = 0;
	sgx_launch_token_t token = {0};

	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);

	return ret;
}

sgx_status_t load_shadow(void) {
	FILE *file_seal;

        file_seal = fopen(SEALED_SHADOW, "rb");

        if (file_seal != NULL) {
	        uint32_t file_length;
		sgx_sealed_data_t *p_sealed_data;
		sgx_status_t ret = SGX_ERROR_UNEXPECTED;

		fseek(file_seal, 0, SEEK_END);
	        file_length = ftell(file_seal);
	        fseek(file_seal, 0, SEEK_SET);
	        
	        p_sealed_data = (sgx_sealed_data_t*)malloc(file_length);
	        fread(p_sealed_data, 1, file_length, file_seal);
	        fclose(file_seal);

		ret = ecall_unseal_data(eid, p_sealed_data, file_length);

		return ret;
	} else {
		printf("Open shadow error\n");
		return 1;
	}
}

sgx_status_t verify_user_pwd(sgx_enclave_id_t enclave_id, sgx_aes_gcm_data_t* message, size_t message_size, sgx_aes_gcm_data_t* response, size_t response_size) {
	return ecall_verify_user_pwd(eid, enclave_id, message, message_size, response, response_size);
}

sgx_status_t session_request(sgx_enclave_id_t enclave_id, sgx_dh_msg1_t *dh_msg1) {
	return ecall_session_request(eid, enclave_id, dh_msg1);
}

sgx_status_t exchange_report(sgx_enclave_id_t enclave_id, sgx_dh_msg2_t *dh_msg2, sgx_dh_msg3_t *dh_msg3, sgx_key_128bit_t *dh_aek) {
	return ecall_exchange_report(eid, enclave_id, dh_msg2, dh_msg3, dh_aek);
}
