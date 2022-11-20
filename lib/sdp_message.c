/*
 * sdp_message.c
 *
 *  Created on: Apr 5, 2016
 *      Author: Daniel Bailey
 */

#include "sdp_ctrl_client.h"

#include <unistd.h>
#include <json-c/json.h>
#include <string.h>
#include "sdp_message.h"
#include "sdp_log_msg.h"

// JSON message strings
const char *sdp_key_action                    = "action";
const char *sdp_key_stage                     = "stage";
const char *sdp_key_data                      = "data";

/*homeSDP*/
const char *sdp_action_authenticate_request	  = "authenticate_request";
const char *sdp_action_stanza_update_request  = "stanza_update_request";
const char *sdp_action_stanza_update		  = "stanza_update";
const char *sdp_action_stanza_ack			  = "stanza_update_ack";
const char *root_check			              = "/root";
/*end*/

const char *sdp_action_credentials_good       = "credentials_good";
const char *sdp_action_keep_alive             = "keep_alive";
const char *sdp_action_cred_update            = "credential_update";
const char *sdp_action_cred_update_request    = "credential_update_request";
const char *sdp_action_cred_ack               = "credential_update_ack";
const char *sdp_action_access_refresh         = "access_refresh";
const char *sdp_action_access_refresh_request = "access_refresh_request";
const char *sdp_action_access_update          = "access_update";
const char *sdp_action_access_remove          = "access_remove";
const char *sdp_action_access_ack             = "access_ack";
const char *sdp_action_service_refresh         = "service_refresh";
const char *sdp_action_service_refresh_request = "service_refresh_request";
const char *sdp_action_service_update          = "service_update";
const char *sdp_action_service_remove          = "service_remove";
const char *sdp_action_service_ack             = "service_ack";
const char *sdp_action_bad_message            = "bad_message";
const char *sdp_action_connection_update      = "connection_update";

const char *sdp_stage_error                   = "error";
const char *sdp_stage_fulfilling              = "fulfilling";
const char *sdp_stage_requesting              = "requesting";
const char *sdp_stage_fulfilled               = "fulfilled";
const char *sdp_stage_unfulfilled             = "unfulfilled";



static int sdp_get_required_json_string_field(const char *key, json_object *jdata, char **r_field)
{
    json_object *jobj;

    // jdata should be a json object containing multiple fields
    // use the key arg to extract a specific field
    if( !json_object_object_get_ex(jdata, key, &jobj))
    {
        log_msg(LOG_ERR, "Failed to find json data field with key: %s", key);
        return SDP_ERROR_INVALID_MSG;
    }

    if(json_object_get_type(jobj) != json_type_string)
    {
        log_msg(LOG_ERR,
            "Found json data field with key %s BUT field was not json_type_string as expected",
            key);
        return SDP_ERROR_INVALID_MSG;
    }

    if((*r_field = strndup(json_object_get_string(jobj), SDP_MSG_FIELD_MAX_LEN)) == NULL)
    {
        return SDP_ERROR_MEMORY_ALLOCATION;
    }

    log_msg(LOG_DEBUG, "JSON parser extracted field value: %s", *r_field);

    return SDP_SUCCESS;
}

int sdp_get_json_string_field(const char *key, json_object *jdata, char **r_field)
{
    json_object *jobj;

    // jdata should be a json object containing multiple fields
    // use the key arg to extract a specific field
    if( !json_object_object_get_ex(jdata, key, &jobj))
    {
        return SDP_ERROR_FIELD_NOT_PRESENT;
    }

    if(json_object_get_type(jobj) != json_type_string)
    {
        log_msg(LOG_ERR,
            "Found json data field with key %s BUT field was not json_type_string as expected",
            key);
        return SDP_ERROR_INVALID_MSG;
    }

    if((*r_field = strndup(json_object_get_string(jobj), SDP_MSG_FIELD_MAX_LEN)) == NULL)
    {
        return SDP_ERROR_MEMORY_ALLOCATION;
    }

    log_msg(LOG_DEBUG, "JSON parser extracted field value: %s", *r_field);

    return SDP_SUCCESS;
}

int sdp_get_json_int_field(const char *key, json_object *jdata, int *r_field)
{
    json_object *jobj;

    // jdata should be a json object containing multiple fields
    // use the key arg to extract a specific field
    if( !json_object_object_get_ex(jdata, key, &jobj))
    {
        return SDP_ERROR_FIELD_NOT_PRESENT;
    }

    if(json_object_get_type(jobj) != json_type_int)
    {
        log_msg(LOG_ERR,
            "Found json data field with key %s BUT field was not json_type_int as expected",
            key);
        return SDP_ERROR_INVALID_MSG;
    }

    *r_field = json_object_get_int(jobj);

    log_msg(LOG_DEBUG, "JSON parser extracted field value: %d", *r_field);

    return SDP_SUCCESS;
}

static int sdp_get_message_action(json_object *jmsg, ctrl_action_t *r_action)
{
    int rv = SDP_ERROR_INVALID_MSG;
    char *action_str = NULL;
    ctrl_action_t action = INVALID_CTRL_ACTION;

    if((rv = sdp_get_required_json_string_field(sdp_key_action, jmsg, &action_str)) != SDP_SUCCESS)
        return rv;

    if(strncmp(action_str, sdp_action_credentials_good, strlen(sdp_action_credentials_good)) == 0)
        action = CTRL_ACTION_CREDENTIALS_GOOD;

    else if(strncmp(action_str, sdp_action_keep_alive, strlen(sdp_action_keep_alive)) == 0)
        action = CTRL_ACTION_KEEP_ALIVE;

    else if(strncmp(action_str, sdp_action_cred_update, strlen(sdp_action_cred_update)) == 0)
        action = CTRL_ACTION_CREDENTIAL_UPDATE;

    else if(strncmp(action_str, sdp_action_service_refresh, strlen(sdp_action_service_refresh)) == 0)
        action = CTRL_ACTION_SERVICE_REFRESH;

    else if(strncmp(action_str, sdp_action_service_update, strlen(sdp_action_service_update)) == 0)
        action = CTRL_ACTION_SERVICE_UPDATE;

    else if(strncmp(action_str, sdp_action_service_remove, strlen(sdp_action_service_remove)) == 0)
        action = CTRL_ACTION_SERVICE_REMOVE;

    else if(strncmp(action_str, sdp_action_access_refresh, strlen(sdp_action_access_refresh)) == 0)
        action = CTRL_ACTION_ACCESS_REFRESH;

    else if(strncmp(action_str, sdp_action_access_update, strlen(sdp_action_access_update)) == 0)
        action = CTRL_ACTION_ACCESS_UPDATE;

    else if(strncmp(action_str, sdp_action_access_remove, strlen(sdp_action_access_remove)) == 0)
        action = CTRL_ACTION_ACCESS_REMOVE;

    else if(strncmp(action_str, sdp_action_bad_message, strlen(sdp_action_bad_message)) == 0)
        action = CTRL_ACTION_BAD_MESSAGE;

	/*homeSDP*/
	else if(strncmp(action_str, sdp_action_stanza_update, strlen(sdp_action_stanza_update)) == 0)
        action = CTRL_ACTION_STANZA_UPDATE;

    free(action_str);

    if(action == INVALID_CTRL_ACTION)
        return rv;

    *r_action = action;
    return SDP_SUCCESS;
}


int  sdp_message_make(const char *action, const json_object *data, char **r_out_msg)
{
    char *out_msg = NULL;
    const char *json_string;
    json_object *jout_msg = json_object_new_object();
    int msg_len = 0;

    if(jout_msg == NULL)
        return SDP_ERROR_MEMORY_ALLOCATION;

    if(action == NULL)
        return SDP_ERROR_INVALID_MSG;

    json_object_object_add(jout_msg, sdp_key_action,  json_object_new_string(action));

    if(data != NULL)
        json_object_object_add(jout_msg, sdp_key_data, json_object_get((json_object*)data));

    json_string = json_object_to_json_string(jout_msg);
    if((msg_len = strnlen(json_string, SDP_MSG_MAX_LEN)) >= SDP_MSG_MAX_LEN )
    {
    	log_msg(LOG_ERR, "sdp_message_make() message exceeds max len %d", SDP_MSG_MAX_LEN);
    	if(jout_msg != NULL && json_object_get_type(jout_msg) != json_type_null) json_object_put(jout_msg);
    	return SDP_ERROR_INVALID_MSG_LONG;
    }

    out_msg = strndup(json_string, msg_len);

    if(jout_msg != NULL && json_object_get_type(jout_msg) != json_type_null) json_object_put(jout_msg);

    if(out_msg == NULL)
        return SDP_ERROR_MEMORY_ALLOCATION;

    *r_out_msg = out_msg;
    return SDP_SUCCESS;
}


int sdp_message_process(const char *msg, ctrl_action_t *r_action, void **r_data)
{
    json_object *jmsg, *jdata;
    int rv = SDP_ERROR_INVALID_MSG;
    //ctrl_response_result_t result = BAD_RESULT;
    ctrl_action_t action = INVALID_CTRL_ACTION;

    // parse the msg string into json objects
    jmsg = json_tokener_parse(msg);

    // find and interpret the message action
    if((rv = sdp_get_message_action(jmsg, &action)) != SDP_SUCCESS)
        goto cleanup;

    // if it's 'credentials good', nothing else to parse
    if(action == CTRL_ACTION_CREDENTIALS_GOOD)
    {
        goto cleanup;
    }

    // if it's keep alive, nothing else to parse
    if(action == CTRL_ACTION_KEEP_ALIVE)
    {
        goto cleanup;
    }


	if(action == CTRL_ACTION_STANZA_UPDATE)
    {
        log_msg(LOG_WARNING, "Received stanza update message");

        if((rv = sdp_message_parse_stanza_fields(jmsg, r_data)) != SDP_SUCCESS)
        {
            log_msg(LOG_ERR, "Failed to parse new stanza data");
        }
		
		goto cleanup;
    }

    // if data field is missing, flunk out
    if( !json_object_object_get_ex(jmsg, sdp_key_data, &jdata))
    {
        rv = SDP_ERROR_INVALID_MSG;
        goto cleanup;
    }

    log_msg(LOG_DEBUG, "Data portion of controller's message:");
    log_msg(LOG_DEBUG, "%s", json_object_to_json_string_ext(jdata, JSON_C_TO_STRING_PRETTY));


    if(action == CTRL_ACTION_CREDENTIAL_UPDATE)
    {
        log_msg(LOG_WARNING, "Received credential update message");

        if((rv = sdp_message_parse_cred_fields(jdata, r_data)) != SDP_SUCCESS)
        {
            log_msg(LOG_ERR, "Failed to parse new credential data");
        }
    }
    else if(action == CTRL_ACTION_SERVICE_REFRESH ||
    		action == CTRL_ACTION_SERVICE_UPDATE ||
			action == CTRL_ACTION_SERVICE_REMOVE ||
			action == CTRL_ACTION_ACCESS_REFRESH ||
			action == CTRL_ACTION_ACCESS_UPDATE ||
    		action == CTRL_ACTION_ACCESS_REMOVE)
    {
        log_msg(LOG_WARNING, "Received service or access data message");

        // verify the data is an array
        if(json_object_get_type(jdata) != json_type_array)
        {
            log_msg(LOG_ERR, "jdata object was not json_type_array as expected");
            rv = SDP_ERROR_INVALID_MSG;
            goto cleanup;
        }

        // increment the reference count to the data portion of the json message
        *r_data = (void*)json_object_get(jdata);
    }
    else if(action == CTRL_ACTION_BAD_MESSAGE)
    {
        log_msg(LOG_ERR, "Received notice from controller that it received the following bad message:");
        log_msg(LOG_ERR, "%s", json_object_to_json_string_ext(jdata, JSON_C_TO_STRING_PRETTY));
    }


cleanup:

    // free the main json message object
    // if the message was good, jdata already
    // holds a ref to just the data portion
	if(jmsg != NULL && json_object_get_type(jmsg) != json_type_null) json_object_put(jmsg);

    if(rv == SDP_SUCCESS)
    {
        *r_action = action;
        rv = SDP_SUCCESS;
    }

    return rv;
}

/*homeSDP*/
int sdp_message_parse_stanza_fields(json_object *jmsg, void **r_stanzas)
{
	sdp_stanzas_t stanzas = NULL;
	json_object *arrayJobj, *indexJobj;
	int rv = SDP_ERROR_INVALID_MSG;
	int index;
	int i;

	if(jmsg == NULL)
	{
		log_msg(LOG_ERR, "Trying to parse stanza fields, but jdata is NULL");
		return rv;
	}

	
	//printf("[myDebug] object type: %d\n", json_object_get_type(json_object_object_get(jmsg, "action")));
	//printf("[myDebug] object type: %d\n", json_object_get_type(json_object_object_get(jmsg, "index")));

	arrayJobj = json_object_object_get(jmsg, sdp_key_data);

	//printf("[myDebug] object type: %d\n", json_object_get_type(arrayJobj));

	for(i = 0; i < json_object_array_length(arrayJobj); i++)
	{
		indexJobj = json_object_array_get_idx(arrayJobj, i);

	    // allocate memory
	    if((stanzas = calloc(1, sizeof *stanzas)) == NULL)
    	    return (SDP_ERROR_MEMORY_ALLOCATION);

	    // extract stanza_name
	    if((rv = sdp_get_json_string_field("STANZA_NAME", indexJobj, &(stanzas->stanza_name))) != SDP_SUCCESS)
	       	goto error;
	
	    // extract sdp_id
	    if((rv = sdp_get_json_int_field("SDP_ID", indexJobj, &(stanzas->sdp_id))) != SDP_SUCCESS)
	        goto error;
	
	    // extract allow_ip
	    if((rv = sdp_get_json_string_field("ALLOW_IP", indexJobj, &(stanzas->allow_ip))) != SDP_SUCCESS)
	        goto error;
	
	    // extract service_ids
	    if((rv = sdp_get_json_int_field("SERVICE_IDS", indexJobj, &(stanzas->service_ids))) != SDP_SUCCESS)
	        goto error;

		// extract spa_server
	    if((rv = sdp_get_json_string_field("SPA_SERVER", indexJobj, &(stanzas->spa_server))) != SDP_SUCCESS)
	        goto error;

    	// extract key_base64
	    if((rv = sdp_get_json_string_field("KEY_BASE64", indexJobj, &(stanzas->key_base64))) != SDP_SUCCESS)
	        goto error;

    	// extract hmac_key_base64
	    if((rv = sdp_get_json_string_field("HMAC_KEY_BASE64", indexJobj, &(stanzas->hmac_key_base64))) != SDP_SUCCESS)
	        goto error;

		// use_hmac is set by default
		if((stanzas->use_hmac = strndup("Y", SDP_MSG_FIELD_MAX_LEN)) == NULL)
    	{
        	rv = SDP_ERROR_MEMORY_ALLOCATION;
			goto error;
    	}

		// sdp_ctrl_client_conf is set by default
		if((stanzas->sdp_ctrl_client_conf = strndup("/home/initiatinghost/sdp_ctrl_client.conf", SDP_MSG_FIELD_MAX_LEN)) == NULL)
    	{
    	   	rv = SDP_ERROR_MEMORY_ALLOCATION;
			goto error;
    	}
		
		// write to .fwknoprc with this stanzas;
		sdp_write_stanza_to_fwknoprc(stanzas);

		sdp_message_destroy_stanzas(stanzas);
	}

    // if we got here, all is good
    // provide the credentials structure
    return SDP_SUCCESS;

error:
	sdp_message_destroy_stanzas(stanzas);
    return rv;
}

//homeSDP need to mod
int sdp_write_stanza_to_fwknoprc(sdp_stanzas_t stanzas) 
{

    char *HOME;
    FILE *fp;
    char path[50];
 
    HOME = getenv("HOME");
    if(strncmp(HOME, root_check,  strlen(root_check)) == 0){
        strncat(path, HOME,strlen(HOME));
        strncat(path, "/gate.fwknoprc",strlen("/gate.fwknoprc"));
	    fp = fopen(path, "a");
    }
    else{
        strncat(path, HOME,strlen(HOME));
        strncat(path, "/gate.fwknoprc",strlen("/.fwknoprc"));
	    fp = fopen(path, "a");
    }
	
	fprintf(fp, "\n[%s]\n",stanzas->stanza_name);
	fprintf(fp, "SDP_ID\t%d\n",stanzas->sdp_id);
	fprintf(fp, "ALLOW_IP\t%s\n",stanzas->allow_ip);
	fprintf(fp, "SERVICE_IDS\t%d\n",stanzas->service_ids);
	fprintf(fp, "SPA_SERVER\t%s\n",stanzas->spa_server);
	fprintf(fp, "KEY_BASE64\t%s\n",stanzas->key_base64);
	fprintf(fp, "HMAC_KEY_BASE64\t%s\n",stanzas->hmac_key_base64);
	fprintf(fp, "USE_HMAC\t%s\n",stanzas->use_hmac);
	fprintf(fp, "SDP_CTRL_CLIENT_CONF\t%s\n",stanzas->sdp_ctrl_client_conf);

	fclose(fp);

	int rv = SDP_SUCCESS;

	return rv;
}

int sdp_message_parse_cred_fields(json_object *jdata, void **r_creds)
{
    sdp_creds_t creds = NULL;
    int rv = SDP_ERROR_INVALID_MSG;

    if(jdata == NULL)
    {
        log_msg(LOG_ERR, "Trying to parse credential fields, but jdata is NULL");
        return rv;
    }

    // allocate memory
    if((creds = calloc(1, sizeof *creds)) == NULL)
        return (SDP_ERROR_MEMORY_ALLOCATION);

    // extract encryption key
    if((rv = sdp_get_required_json_string_field("spa_encryption_key_base64", jdata, &(creds->encryption_key))) != SDP_SUCCESS)
        goto error;

    // extract hmac key
    if((rv = sdp_get_required_json_string_field("spa_hmac_key_base64", jdata, &(creds->hmac_key))) != SDP_SUCCESS)
        goto error;

    // extract tls client cert
    if((rv = sdp_get_required_json_string_field("tls_cert", jdata, &(creds->tls_cert))) != SDP_SUCCESS)
        goto error;

    // extract tls client key
    if((rv = sdp_get_required_json_string_field("tls_key", jdata, &(creds->tls_key))) != SDP_SUCCESS)
        goto error;

    // if we got here, all is good
    // provide the credentials structure
    *r_creds = (void*)creds;
    return SDP_SUCCESS;

error:
    sdp_message_destroy_creds(creds);
    return rv;
}

//homeSDP
void sdp_message_destroy_stanzas(sdp_stanzas_t stanzas)
{


    if(stanzas == NULL)
        return;

    if(stanzas->stanza_name != NULL)
        free(stanzas->stanza_name);

    if(stanzas->sdp_id != 0)
		stanzas->sdp_id = 0;

    if(stanzas->allow_ip != NULL)
        free(stanzas->allow_ip);

	if(stanzas->service_ids != 0)
        stanzas->service_ids = 0;

    if(stanzas->spa_server != NULL)
        free(stanzas->spa_server);

    if(stanzas->key_base64 != NULL)
        free(stanzas->key_base64);

    if(stanzas->hmac_key_base64 != NULL)
        free(stanzas->hmac_key_base64);

    if(stanzas->use_hmac != NULL)
        free(stanzas->use_hmac);

    if(stanzas->sdp_ctrl_client_conf != NULL)
        free(stanzas->sdp_ctrl_client_conf);

    free(stanzas);

	//printf("[myDebug] after\n");

}

void sdp_message_destroy_creds(sdp_creds_t creds)
{
    if(creds == NULL)
        return;

    if(creds->encryption_key != NULL)
        free(creds->encryption_key);

    if(creds->hmac_key != NULL)
        free(creds->hmac_key);

    if(creds->tls_cert != NULL)
        free(creds->tls_cert);

    if(creds->tls_key != NULL)
        free(creds->tls_key);

    free(creds);
}


