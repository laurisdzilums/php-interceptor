/**
 * PHP Interceptor Extension
 *
 * @author Viesturs Kavacs <kavackys@gmail.com>
 * @version 1.0
 * @date 15.11.2011.
 *
 * This source file is subject to version 2.02 of the PHP license,
 * that is bundled with this package in the file LICENSE, and is
 * available at through the world-wide-web at
 * http://www.php.net/license/2_02.txt
 * If you did not receive a copy of the PHP license and are unable to
 * obtain it through the world-wide-web, please send a note to
 * license@php.net so we can mail you a copy immediately.
 *
 * Based on Intercept Extension by Gabriel Ricard <gabe@php.net>
 * http://pecl.php.net/package/intercept
 *
 */

#ifdef HAVE_CONFIG_H
	#include "config.h"
#endif

#include "stdio.h"
#include "time.h"
#include "php.h"
#include "php_ini.h"
#include "ext/standard/basic_functions.h"
#include "ext/standard/info.h"
#include "php_interceptor.h"

#ifdef LOG_WITH_SQLITE
	#include <sqlite3.h>
#endif

ZEND_DLEXPORT void interceptor_execute_internal(zend_execute_data *execute_data_ptr, int return_value_used TSRMLS_DC);
ZEND_DLEXPORT void (*interceptor_old_zend_execute_internal)(zend_execute_data *execute_data_ptr, int return_value_used TSRMLS_DC);

ZEND_DLEXPORT void interceptor_execute(zend_op_array *op_array TSRMLS_DC);
ZEND_DLEXPORT void (*interceptor_old_execute)(zend_op_array *op_array TSRMLS_DC);

ZEND_DECLARE_MODULE_GLOBALS(interceptor)

// True global resources - no need for thread safety here
static int le_interceptor;

/**
 * List user-visible function
 */
function_entry interceptor_functions[] = {
	PHP_FE(interceptor_add_callname,	NULL)
	{NULL, NULL, NULL}
};

/**
 * Module entry - register init and shutdown functions
 */
zend_module_entry interceptor_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
	STANDARD_MODULE_HEADER,
#endif
	"interceptor",
	interceptor_functions,
	PHP_MINIT(interceptor),
	PHP_MSHUTDOWN(interceptor),
	PHP_RINIT(interceptor),
	PHP_RSHUTDOWN(interceptor),
	PHP_MINFO(interceptor),
#if ZEND_MODULE_API_NO >= 20010901
	"1.0 F-14 Tomcat",
#endif
	STANDARD_MODULE_PROPERTIES
};

/**
 * Module
 */
#ifdef COMPILE_DL_INTERCEPTOR
	ZEND_GET_MODULE(interceptor)
#endif

/**
 * PHP ini entry registration
 */
PHP_INI_BEGIN()
	PHP_INI_ENTRY("interceptor.max_depth", 3, PHP_INI_ALL, NULL)
	PHP_INI_ENTRY("interceptor.log_type", LOG_TEXT, PHP_INI_ALL, NULL)
	PHP_INI_ENTRY("interceptor.log_timestamp", "%d.%m.%Y %H:%M:%S", PHP_INI_ALL, NULL)
	PHP_INI_ENTRY("interceptor.log_file", "/var/log/php_interceptor.log", PHP_INI_ALL, NULL)
	
#ifdef LOG_WITH_SQLITE
	PHP_INI_ENTRY("interceptor.log_sqlite_db", "/var/log/php_interceptor.sqlite3", PHP_INI_ALL, NULL)
#endif
PHP_INI_END()

/**
 *
 * Module initialization
 *		
 */
PHP_MINIT_FUNCTION(interceptor)
{
	REGISTER_INI_ENTRIES();

	REGISTER_LONG_CONSTANT("INTERCEPT_BEFORE", INTERCEPT_BEFORE, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("INTERCEPT_AFTER", INTERCEPT_AFTER, CONST_CS | CONST_PERSISTENT);

	// Save old zend_execute function and override with ours
	interceptor_old_execute = zend_execute;
	zend_execute = interceptor_execute;

	// Save old zend_execute_internal (for internal PHP calls) function and override with ours
	interceptor_old_zend_execute_internal = zend_execute_internal;
	zend_execute_internal = interceptor_execute_internal;

	return SUCCESS;
}

/**
 *
 * Module shutdown
 *		
 */
PHP_MSHUTDOWN_FUNCTION(interceptor)
{
	UNREGISTER_INI_ENTRIES();
	
	// Restore call executors	
	zend_execute = interceptor_old_execute;
	zend_execute_internal = interceptor_old_zend_execute_internal;

	return SUCCESS;
}

/**
 *
 * Request initialization
 *		
 */
PHP_RINIT_FUNCTION(interceptor)
{
	// Handler arrays
	MAKE_STD_ZVAL(IntG(pre_interceptor_handlers));
	array_init(IntG(pre_interceptor_handlers));
	MAKE_STD_ZVAL(IntG(post_interceptor_handlers));
	array_init(IntG(post_interceptor_handlers));
	
	// Depth counter to escape infinite loops, where infinite = while memory !full
	IntG(depth) = 0;
	
	// Format timestamp for intercept log
	time_t rawtime;
	struct tm * timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(IntG(timestamp), 40, INI_STR("interceptor.log_timestamp"), timeinfo);

#ifdef LOG_WITH_SQLITE
	// @TODO: move to MINIT?
	// If we're using SQLite, make sure that there will be a database and a table
	if (INI_INT("interceptor.log_type") == LOG_SQLITE)
	{
		sqlite3 *db;
		int ret;
		
		// Open DB file = create DB if not exists
		ret = sqlite3_open(INI_STR("interceptor.log_sqlite_db"), &db);
		if (ret)
		{
			php_error_docref1(NULL TSRMLS_CC, "sqlite", E_ERROR,
						  "Unable to connect SQLite database \"%s\". Error: %s!", INI_STR("interceptor.log_sqlite_db"), sqlite3_errmsg(db));
			
			return FAILURE;
		}
		
		// Create table
		char *err_msg;
		ret = sqlite3_exec(
			db,
			"CREATE TABLE IF NOT EXISTS intercepts (\
				id INTEGER PRIMARY KEY,\
				timestamp STRING,\
				pid INTEGER,\
				depth INTEGER,\
				type STRING,\
				callname STRING,\
				file STRING,\
				line INTEGER,\
				handler_status STRING,\
				handler_response STRING\
			)",
			NULL, // No callback
			NULL, // No param to callback
			&err_msg // Just error message
		);
		
		if (ret)
		{
			php_error_docref1(NULL TSRMLS_CC, "sqlite", E_ERROR,
						  "Unable to create SQLite table. Error: \"%s\"!", err_msg);
	  		
			sqlite3_free(err_msg);
			sqlite3_close(db);
			
			return FAILURE;
		}
		
		sqlite3_close(db);
		chmod(INI_STR("interceptor.log_sqlite_db"), 0666);
	}
#endif	
	
	return SUCCESS;
}

/**
 *
 * Request shutdown
 *		
 */
PHP_RSHUTDOWN_FUNCTION(interceptor)
{
	zval_ptr_dtor(&IntG(pre_interceptor_handlers));
	zval_ptr_dtor(&IntG(post_interceptor_handlers));
	
	return SUCCESS;
}

/**
 *
 * Module info message
 *		
 */
PHP_MINFO_FUNCTION(interceptor)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "interceptor support", "enabled");
	php_info_print_table_end();

	DISPLAY_INI_ENTRIES();
}

/**
 *
 * Add intercept for given call name
 *
 * @param string target Call name to intercept ("function", "object::method", "object->method")
 * @param string handler Handler function name
 * @param long flags Intercept before/after call
 *
 */
PHP_FUNCTION(interceptor_add_callname)
{
	zval *handler;
	zval *target;
	char *handler_name, *target_name;
	long flags;
	zval *interceptor_handlers;
	zend_function *func;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "zz|l", &target, &handler, &flags ) == FAILURE) {
		return;
	}
	
	// Check if string is passed
	// And this is the only check, because we can't check callability,
	// if dynamic constructs are to be intercepted, e.g. Exception->__construct
	if (Z_TYPE_P(target) != IS_STRING) {
	
		php_error_docref1(NULL TSRMLS_CC, "target", E_ERROR,
						  "Passed target is not a valid callname string");
		
		RETURN_FALSE;
		
	}
	
	// Ok, convert to normal string
	target_name = Z_STRVAL_P(target);
	
	/* efree(target_name) only if using this callability check */
	/*if (!zend_is_callable(target, 0, &target_name)) {
		/*php_error_docref1(NULL TSRMLS_CC, target_name, E_WARNING,
						  "%s is not a valid function", target_name);
		efree(target_name);
		RETURN_FALSE;*/ /*
	}*/

	// Intercept after or before?
	if (flags & INTERCEPT_AFTER) {
		interceptor_handlers = IntG(post_interceptor_handlers);
	}
	else {
		interceptor_handlers = IntG(pre_interceptor_handlers);
	}
	
	// Check if handler for this callname is already set	
	if (zend_hash_exists(Z_ARRVAL_P(interceptor_handlers), target_name, strlen(target_name) + 1) ) {
	
		php_error_docref1(NULL TSRMLS_CC, target_name, E_WARNING,
						  "%s already has a registered interceptor", target_name);
		//efree(target_name);

		RETURN_FALSE;
		
	}

	// Convert handler to string
   	convert_to_string(handler);

   	// Handler must be callable
	if (!zend_is_callable(handler, 0, &handler_name)) {
	
		php_error_docref1(NULL TSRMLS_CC, handler_name, E_WARNING,
						  "%s is not a valid handler function", handler_name);
						  
		efree(handler_name);
		//efree(target_name);
		
		RETURN_FALSE;
		
	}
	else {
	
		// Callable, but must check, that it's a user-defined function
		// (how otherwise call_user_func would work?)
		
		// So, check against all registered functions
		if( zend_hash_find(EG(function_table), handler_name, strlen(handler_name) + 1, (void **) &func) != FAILURE ) {
		
			// And show error, if it's user's
			if (func->type != ZEND_USER_FUNCTION) {
			
				php_error_docref1(NULL TSRMLS_CC, handler_name, E_WARNING,
								  "%s is not a user-defined handler function", handler_name);
								  
				efree(handler_name);
				//efree(target_name);
				
				RETURN_FALSE;
				
			}	
		}
	}

	add_assoc_string(interceptor_handlers, target_name, handler_name, 1);
	
	efree(handler_name);
	//efree(target_name);
	
	RETURN_TRUE;
}

/**
 *
 * Gets active function call name (function, object->function, object::function)
 *
 * Originally borrowed from APD - apd_get_active_function_name(), then borrowed
 * from original Intercept extension
 *
 * @param zend_op_array op_array
 *
 * @return char Call name
 *
 */
char *interceptor_get_active_function_name(zend_op_array *op_array TSRMLS_DC)
{
	char *funcname = NULL;
	int curSize = 0;
	zend_execute_data *execd = NULL;
	char *tmpfname;
	char *classname;
	int classnameLen;
	int tmpfnameLen;
  
	execd = EG(current_execute_data);
	if(execd) {
		tmpfname = execd->function_state.function->common.function_name;
		if(tmpfname) {
			tmpfnameLen = strlen(tmpfname);
			if(execd->object) {
				classname = Z_OBJCE(*execd->object)->name;
				classnameLen = strlen(classname);
				funcname = (char *)emalloc(classnameLen + tmpfnameLen + 3);
				snprintf(funcname, classnameLen + tmpfnameLen + 3, "%s->%s",
						 classname, tmpfname);
			}
			else if(execd->function_state.function->common.scope) {
				classname = execd->function_state.function->common.scope->name;
				classnameLen = strlen(classname);
				funcname = (char *)emalloc(classnameLen + tmpfnameLen + 3);
				snprintf(funcname, classnameLen + tmpfnameLen + 3, "%s::%s",
						 classname, tmpfname);
			}
			else {
				funcname = estrdup(tmpfname);
			}
		} 
		else {
			switch (execd->opline->op2.u.constant.value.lval) {
			case ZEND_EVAL:
				funcname = estrdup("eval");
				break;
			case ZEND_INCLUDE:
				funcname = estrdup("include");
				break;
			case ZEND_REQUIRE:
				funcname = estrdup("require");
				break;
			case ZEND_INCLUDE_ONCE:
				funcname = estrdup("include_once");
				break;
			case ZEND_REQUIRE_ONCE:
				funcname = estrdup("require_once");
				break;
			default:
				funcname = estrdup("???");
				break;
			}
		}
	} 
	else {
		funcname = estrdup("main");
	}
	return funcname;
}

/**
 *
 * Write log data to text file (default option)
 *
 * @param char *intercepted_call Call name
 * @param char *timestamp Formatted timestamp
 * @param int process_id Process id
 * @param short depth Current depth
 * @param char *intercept_type "bef"/"aft"
 * @param char *filename Filename of call
 * @param int line Line number of call
 * @param char *handler_call_status Status of handler call
 * @param char *returned_string Returned value of handler call
 *
 */
void log_write_text(char *intercepted_call, char *timestamp, int process_id, short depth,
	char *intercept_type, char *filename, int line, char *handler_call_status, char *returned_string)
{
	FILE *f;
	f = fopen(INI_STR("interceptor.log_file"), "a+");
	
	fprintf(f, "%s %d %d %s %s \"%s\" %d %s %s\r\n", timestamp, process_id, depth, intercept_type, intercepted_call, filename, line, handler_call_status, returned_string);
	
	fclose(f);
	chmod(INI_STR("interceptor.log_file"), 0666);
}

#ifdef LOG_WITH_SQLITE
/**
 *
 * Write log data to SQLite database
 *
 * @param char *intercepted_call Call name
 * @param char *timestamp Formatted timestamp
 * @param int process_id Process id
 * @param short depth Current depth
 * @param char *intercept_type "bef"/"aft"
 * @param char *filename Filename of call
 * @param int line Line number of call
 * @param char *handler_call_status Status of handler call
 * @param char *returned_string Returned value of handler call
 *
 */
void log_write_sqlite(char *intercepted_call, char *timestamp, int process_id, short depth,
	char *intercept_type, char *filename, int line, char *handler_call_status, char *returned_string)
{
	sqlite3 *db;
	int ret;
	
	// Connect DB
	// :TODO: refactor to function (this & RINIT)
	ret = sqlite3_open(INI_STR("interceptor.log_sqlite_db"), &db);
	if (ret)
	{
		php_error_docref1(NULL TSRMLS_CC, "sqlite", E_ERROR,
					  "Unable to connect SQLite database \"%s\". Error: %s!", INI_STR("interceptor.log_sqlite_db"), sqlite3_errmsg(db));
		
		return;
	}
	
	// Prepare query - %q to escape strings
	char *sql = sqlite3_mprintf("INSERT INTO intercepts\
			(timestamp, pid, depth, type, callname, file, line, handler_status, handler_response)\
			VALUES(\
			'%s', %d, %d, '%q', '%q', '%q', %d, '%q', '%q'\
			);",
		timestamp, process_id, depth, intercept_type, intercepted_call, filename, line, handler_call_status, returned_string);

	// Insert entry	
	char *err_msg;
	ret = sqlite3_exec(
		db,
		sql,
		NULL, // No callback
		NULL, // No param to callback
		&err_msg // Just error message
	);
	sqlite3_free(sql);
	
	// :TODO: refactor to universal error message (this & RINIT)
	if (ret)
	{
		php_error_docref1(NULL TSRMLS_CC, "sqlite", E_ERROR,
					  "Unable to insert row. Error: \"%s\"!", err_msg);
  		
		sqlite3_free(err_msg);
		sqlite3_close(db);
		
		return;
	}
	
	sqlite3_close(db);
}
#endif

/**
 *
 * Saves log entry
 *
 * @param char *intercepted_call Call name
 * @param short type Before/after
 * @param int call_result Success of handler function call
 * @param zval *returned_value Value returned by handler function
 *
 */
void log_save(char *intercepted_call, short type, int call_result, zval *returned_value)
{
	// Gather up all vars for logging
	char *timestamp = IntG(timestamp);
	int process_id = getpid();
	short depth = IntG(depth);
	
	// Where was it intercepted?
	char *intercept_type = "aft";
	if (type == INTERCEPT_BEFORE)
	{
		intercept_type = "bef";
	}
	
	char *filename = zend_get_executed_filename();
	int line = zend_get_executed_lineno();
	
	// What happened?
	char *handler_call_status;
	if (call_result == SUCCESS)
	{
		handler_call_status = "handler_call_ok";
	}
	else if (call_result == FAILURE)
	{
		handler_call_status = "handler_call_failed";
	}
	else if (call_result == FAILURE_MULTI_FAULT)
	{
		handler_call_status = "gone_too_deep";
	}
	else
	{
		handler_call_status = "unknown";
	}
	
	// Get return value of handler call
	char *returned_string = "";
	if ( returned_value != NULL )
	{
		convert_to_string(returned_value);
		returned_string = Z_STRVAL_P(returned_value);
	}
	
	// Select logger function
	if (0)
	{
		// This is for auto-calling default, if no other logging types are defined, eg. compiled w/a SQLite
	}
#ifdef LOG_WITH_SQLITE
	else if (INI_INT("interceptor.log_type") == LOG_SQLITE)
	{
		log_write_sqlite(intercepted_call, timestamp, process_id, depth,
			intercept_type, filename, line, handler_call_status, returned_string);
	}
#endif
	else
	{
		// This is default
		log_write_text(intercepted_call, timestamp, process_id, depth,
			intercept_type, filename, line, handler_call_status, returned_string);
	}
}

/**
 *
 * Check if not too deep in in[ter]ception
 *
 * @param char *intercepted_call Call name
 * @param short type Before/after
 *
 * @return short Ok or too deep
 *
 */
short depth_test(char *intercepted_call, short type)
{
	if ( IntG(depth) > INI_INT("interceptor.max_depth") )
	{
		log_save(intercepted_call, type, FAILURE_MULTI_FAULT, NULL);
		return 0;
	}
	else
	{
		return 1;
	}
}

/**
 *
 * Calls requested user function
 *
 * @param zval **function_name
 * @param char *intercepted_call_name
 *
 */
void call_handler(zval **function_name, char *intercepted_call_name)
{
	IntG(depth)++;
	if ( !depth_test(intercepted_call_name, INTERCEPT_BEFORE) )
	{
		IntG(depth)--;
		return;
	}
	
	int call_status;
	zval *function_return_value = NULL;
	zval *args[1];
	//zval **object;
	
	/* :TODO: (from original Intercept) if func name is array copy array[1] to target_name (this is the method name) and  copy array[0] to object name */
	
	// Set up arguments
	MAKE_STD_ZVAL(args[0]);
	MAKE_STD_ZVAL(function_return_value);
	ZVAL_STRING(args[0], intercepted_call_name, 0);
	
	call_status = call_user_function(EG(function_table),
									NULL,
									*function_name,
									function_return_value,
									1, // argc
									args TSRMLS_CC); // argv
	
	log_save(intercepted_call_name, INTERCEPT_BEFORE, call_status, function_return_value);
	
	efree(function_return_value);
	efree(args[0]);
	
	IntG(depth)--;
}

/**
 *
 * Override for user-defined function execution
 *
 * @param zend_op_array *op_array
 *
 */
ZEND_API void interceptor_execute(zend_op_array *op_array TSRMLS_DC)
{
	char *intercepted_call_name = NULL;
	zval **handler_name;

	intercepted_call_name = interceptor_get_active_function_name(op_array TSRMLS_CC);
	
	// If having PRE-INTERCEPTORS
	if (zend_hash_find(Z_ARRVAL_P(IntG(pre_interceptor_handlers)), intercepted_call_name, strlen(intercepted_call_name) + 1, (void **) &handler_name) != FAILURE) {
		call_handler(handler_name, intercepted_call_name);
	}
	
	// Call original Zend executor
	interceptor_old_execute(op_array TSRMLS_CC);
	
	// If having POST-INTERCEPTORS
	if (zend_hash_find(Z_ARRVAL_P(IntG(post_interceptor_handlers)), intercepted_call_name, strlen(intercepted_call_name) + 1, (void **) &handler_name) != FAILURE) {
		call_handler(handler_name, intercepted_call_name);
	}

	efree(intercepted_call_name);
}

/**
 *
 * Override for PHP's internal function execution
 *
 * @param zend_execute_data *execute_data_ptr
 * @param int return_value_used
 *
 */
ZEND_API void interceptor_execute_internal(zend_execute_data *execute_data_ptr, int return_value_used TSRMLS_DC)
{
	char *intercepted_call_name = NULL;
	zval **handler_name;
	zend_execute_data *execd;

	execd = EG(current_execute_data);
	intercepted_call_name = interceptor_get_active_function_name(execd->op_array TSRMLS_CC);
	
	// If having PRE-INTERCEPTORS
	if (zend_hash_find(Z_ARRVAL_P(IntG(pre_interceptor_handlers)), intercepted_call_name, strlen(intercepted_call_name) + 1, (void **) &handler_name) != FAILURE) {
		call_handler(handler_name, intercepted_call_name);
	}
	
	// Original Zend executor
	if (!interceptor_old_zend_execute_internal) {
		execute_internal(execute_data_ptr, return_value_used TSRMLS_CC);
	}
	else {
		interceptor_old_zend_execute_internal(execute_data_ptr, return_value_used TSRMLS_CC);
	}

	// If having POST-INTERCEPTORS
	if (zend_hash_find(Z_ARRVAL_P(IntG(post_interceptor_handlers)), intercepted_call_name, strlen(intercepted_call_name) + 1, (void **) &handler_name) != FAILURE) {
		call_handler(handler_name, intercepted_call_name);
	}

	efree(intercepted_call_name);
}
