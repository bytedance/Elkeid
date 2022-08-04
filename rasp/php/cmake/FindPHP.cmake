# - Find PHP
# This module finds if PHP is installed and determines where the include files
# and libraries are. 
#
# Note, unlike the FindPHP4 module, this module uses the php-config script to
# determine information about the installed PHP configuration.  For Linux
# distributions, this script is normally installed as part of some php-dev or
# php-devel package. See http://php.net/manual/en/install.pecl.php-config.php
# for php-config documentation.
#
# This code sets the following variables:
#  PHP_CONFIG_DIR             = directory containing PHP configuration files
#  PHP_CONFIG_EXECUTABLE      = full path to the php-config binary
#  PHP_EXECUTABLE             = full path to the php binary
#  PHP_EXTENSIONS_DIR         = directory containing PHP extensions
#  PHP_EXTENSIONS_INCLUDE_DIR = directory containing PHP extension headers
#  PHP_INCLUDE_DIRS           = include directives for PHP development
#  PHP_VERSION_NUMBER         = PHP version number in PHP's "vernum" format eg 50303
#  PHP_VERSION_MAJOR          = PHP major version number eg 5
#  PHP_VERSION_MINOR          = PHP minor version number eg 3
#  PHP_VERSION_PATCH          = PHP patch version number eg 3
#  PHP_VERSION_STRING         = PHP version string eg 5.3.3-1ubuntu9.3
#  PHP_FOUND                  = set to TRUE if all of the above has been found.
#

#=============================================================================
# Copyright 2011-2012 Paul Colby
#
# Distributed under the OSI-approved BSD License (the "License");
# see accompanying file LICENSE.md for details.
#
# This software is distributed WITHOUT ANY WARRANTY; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
# See the License for more information.
#=============================================================================
# (To distribute this file outside of CMake, substitute the full
#  License text for the above reference.)

FIND_PROGRAM(PHP_CONFIG_EXECUTABLE NAMES php-config5 php-config4 php-config)

if (PHP_CONFIG_EXECUTABLE)
    execute_process(
            COMMAND
            ${PHP_CONFIG_EXECUTABLE} --configure-options
            OUTPUT_STRIP_TRAILING_WHITESPACE
            OUTPUT_VARIABLE PHP_CONFIG_DIR
    )

    string(REGEX REPLACE ".*--with-config-file-scan-dir=([^ ]*).*" "\\1" PHP_CONFIG_DIR ${PHP_CONFIG_DIR})

    execute_process(
            COMMAND
            ${PHP_CONFIG_EXECUTABLE} --php-binary
            OUTPUT_VARIABLE PHP_EXECUTABLE
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    execute_process(
            COMMAND
            ${PHP_CONFIG_EXECUTABLE} --extension-dir
            OUTPUT_VARIABLE PHP_EXTENSIONS_DIR
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    execute_process(
            COMMAND
            ${PHP_CONFIG_EXECUTABLE} --include-dir
            OUTPUT_VARIABLE PHP_EXTENSIONS_INCLUDE_DIR
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    execute_process(
            COMMAND
            ${PHP_CONFIG_EXECUTABLE} --includes
            OUTPUT_VARIABLE PHP_INCLUDE_DIRS
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    execute_process(
            COMMAND
            ${PHP_CONFIG_EXECUTABLE} --vernum
            OUTPUT_VARIABLE PHP_VERSION_NUMBER
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )

    string(SUBSTRING ${PHP_VERSION_NUMBER} 0 1 PHP_VERSION_MAJOR)
    string(SUBSTRING ${PHP_VERSION_NUMBER} 2 2 PHP_VERSION_MINOR)
    string(SUBSTRING ${PHP_VERSION_NUMBER} 4 2 PHP_VERSION_PATCH)

    string(REGEX REPLACE "^0(.)" "\\1" PHP_VERSION_MINOR ${PHP_VERSION_MINOR})
    string(REGEX REPLACE "^0(.)" "\\1" PHP_VERSION_PATCH ${PHP_VERSION_PATCH})

    execute_process(
            COMMAND
            ${PHP_CONFIG_EXECUTABLE} --version
            OUTPUT_VARIABLE PHP_VERSION_STRING
            OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif (PHP_CONFIG_EXECUTABLE)

MARK_AS_ADVANCED(
        PHP_CONFIG_DIR
        PHP_CONFIG_EXECUTABLE
        PHP_EXECUTABLE
        PHP_EXTENSIONS_DIR
        PHP_EXTENSIONS_INCLUDE_DIR
        PHP_INCLUDE_DIRS
        PHP_VERSION_MAJOR
        PHP_VERSION_MINOR
        PHP_VERSION_PATCH
        PHP_VERSION_NUMBER
        PHP_VERSION_STRING
)

INCLUDE(FindPackageHandleStandardArgs)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(
        PHP
        REQUIRED_VARS
        PHP_EXECUTABLE
        PHP_CONFIG_DIR
        PHP_CONFIG_EXECUTABLE
        PHP_EXTENSIONS_DIR
        PHP_EXTENSIONS_INCLUDE_DIR
        PHP_INCLUDE_DIRS
        PHP_VERSION_NUMBER
        VERSION_VAR PHP_VERSION_STRING
)