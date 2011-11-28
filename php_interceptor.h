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

#ifndef PHP_INTERCEPTOR_H
#define PHP_INTERCEPTOR_H

extern zend_module_entry interceptor_module_entry;
#define phpext_interceptor_ptr &interceptor_module_entry

#ifdef PHP_WIN32
	#define PHP_INTERCEPTOR_API __declspec(dllexport)
#else
	#define PHP_INTERCEPTOR_API
#endif

#ifdef ZTS
	#include "TSRM.h"
#endif

PHP_MINIT_FUNCTION(interceptor);
PHP_MSHUTDOWN_FUNCTION(interceptor);
PHP_RINIT_FUNCTION(interceptor);
PHP_RSHUTDOWN_FUNCTION(interceptor);
PHP_MINFO_FUNCTION(interceptor);

PHP_FUNCTION(interceptor_add_callname);

ZEND_BEGIN_MODULE_GLOBALS(interceptor)
	zval *pre_interceptor_handlers;
	zval *post_interceptor_handlers;
	
	short depth;
	char timestamp[40];
ZEND_END_MODULE_GLOBALS(interceptor)

#ifdef ZTS
	#define IntG(v) TSRMG(interceptor_globals_id, zend_interceptor_globals *, v)
#else
	#define IntG(v) (interceptor_globals.v)
#endif

#define INTERCEPT_BEFORE 1
#define INTERCEPT_AFTER 2

#define LOG_TEXT 1
#define LOG_SQLITE 2

//#define LOG_WITH_SQLITE

#endif	/* PHP_INTERCEPTOR_H */
