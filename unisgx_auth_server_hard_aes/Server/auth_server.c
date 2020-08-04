#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h> /* for glib main loop */
#include "sgx_eid.h"
#include "sgx_urts.h"
#include "../App/Enclave_u.h" //Gerado pelo Edger8r
#include "aes.h"

#define ENCLAVE_FILENAME "/lib/x86_64-linux-gnu/security/enclave.signed.so"
# define SEALED_SHADOW "/home/newton/unisgx/sealed_shadow"

DBusHandlerResult server_get_properties_handler(const char *property, DBusConnection *conn, DBusMessage *reply);
DBusHandlerResult server_get_all_properties_handler(DBusConnection *conn, DBusMessage *reply);
DBusHandlerResult server_message_handler(DBusConnection *conn, DBusMessage *message, void *data);
sgx_status_t create_enclave(void);
sgx_status_t load_shadow(void);
int verify_user_pwd(const char *auth_ret, const char *name, int name_len, const char *password, int password_len, const char *nullok, int nullok_len);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext);

const char *version = "0.1";
const char *iface = "br.ufpr.inf.larsis.UniSGXInterface";
const char *serverName = "br.ufpr.inf.larsis.UniSGX";
const char *objectPath = "/br/ufpr/inf/larsis/Object";
GMainLoop *mainloop;
sgx_enclave_id_t eid = 0;

uint8_t key[16] = { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
uint8_t iv[16]  = { 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext) {
	struct AES_ctx ctx;

	memcpy(ciphertext, plaintext, plaintext_len);
    
	AES_init_ctx_iv(&ctx, key, iv);
	AES_CTR_xcrypt_buffer(&ctx, ciphertext, plaintext_len);

	return plaintext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext) {
	return encrypt(ciphertext, ciphertext_len, plaintext);
}

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
	"      <arg name='name' direction='in' type='s'/>\n"
	"      <arg name='password' direction='in' type='s'/>\n"
	"      <arg name='nullok' direction='in' type='y'/>\n"
	"      <arg type='y' direction='out' />\n"
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

	// fprintf(stderr, "Got D-Bus request: %s.%s on %s\n", dbus_message_get_interface(message), dbus_message_get_member(message), dbus_message_get_path(message));

	/*
	 * Does not allocate any memory; the error only needs to be
	 * freed if it is set at some point.
	 */
	dbus_error_init(&err);

	if (dbus_message_is_method_call(message, iface, "verify_password")) {
		const char* ciphername;
		const char* cipherpassword;
		const char* ciphernullok;
		char auth_ret[16];
		//char name[128], password[128], cnullok[128], cresponse[128];
		//uint8_t cipherret[128];
		//uint8_t nullok;
		int ciphername_len, cipherpassword_len, cipherctrl_len, ret_len = 1;
		unsigned char response = 0;

		//fprintf(stderr, "Starting verify_password\n");

		if (!dbus_message_get_args(message, &err, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &ciphername, &ciphername_len, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &cipherpassword, &cipherpassword_len, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &ciphernullok, &cipherctrl_len, DBUS_TYPE_INVALID)) {
			response = 11;
		}

		//ret_len = decrypt((unsigned char*)ciphername, ciphername_len, name);
		//ret_len = decrypt((unsigned char*)cipherpassword, cipherpassword_len, password);
		//ret_len = decrypt((unsigned char*)ciphernullok, cipherctrl_len, cnullok);
		//nullok = atoi(cnullok);

		//fprintf(stderr, "Parameters OK\n");
		//fprintf(stderr, "Name: %s; Pass: %s\n", name, password);
		//fprintf(stderr, "len: %d\n", cipherctrl_len);

		if((eid == 0) && (response == 0)) {
			//fprintf(stderr, "Criando enclave\n");

			if(create_enclave() != SGX_SUCCESS) {
				response = 3;
			}

			if(load_shadow() != SGX_SUCCESS) {
				response = 1;
			}
		}

		//fprintf(stderr, "Enclave loaded\n");

		if(response == 0) {
			response = verify_user_pwd(auth_ret, ciphername, ciphername_len, cipherpassword, cipherpassword_len, ciphernullok, cipherctrl_len);
		}

		//fprintf(stderr, "verify_user_pwd response %d\n", response);

		if (!(reply = dbus_message_new_method_return(message))) {
			goto fail;
		}

		//itoa(response, cresponse, 10);
		//snprintf(cresponse, sizeof(cresponse), "%d", response);
		//ret_len = encrypt((unsigned char*)cresponse, strlen(cresponse), cipherret);
		uint8_t *p_cipherret = auth_ret;

		dbus_message_append_args(reply, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &p_cipherret, ret_len, DBUS_TYPE_INVALID);

		// printf("Sender: %s\n", dbus_message_get_sender(message));

		//dbus_message_set_destination(reply, dbus_message_get_sender(message));

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

int verify_user_pwd(const char *auth_ret, const char *name, int name_len, const char *password, int password_len, const char *nullok, int nullok_len) {
	sgx_status_t ret = SGX_ERROR_UNEXPECTED;

	ret = ecall_verify_user_pwd(eid, auth_ret, 1, name, name_len, password, password_len, nullok, nullok_len);

	if(ret == SGX_SUCCESS) {
		return 0;
	} else {
		printf("SGX ERROR %d\n", ret);
		return 1;
	}
}
