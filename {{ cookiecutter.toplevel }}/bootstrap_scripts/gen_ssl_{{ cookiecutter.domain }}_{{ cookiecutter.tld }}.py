#!python3.7

import os
import shutil
import subprocess
import sys


PROGRAM_NAME = "gen_ssl_{{ cookiecutter.domain }}_{{ cookiecutter.tld }}.py"
# relative paths evaluated w.r.t. to the CWD
# new host key and crt will be generated if CC_GENERATE_HOST_KEYCSR is "yes"
CC_GENERATE_HOST_KEYCSR = "{{ cookiecutter.ssl_generate_host_crtkey }}".strip().upper()
# if CC_GENERATE_HOST_KEYCSR is yes then will generate CC_HOST_KEY_PATH if it does not exist
# and then CC_HOST_CRT_PATH, if CC_HOST_CRT_PATH exist then it is an error
CC_HOST_KEY_PATH = "{{ cookiecutter.ssl_host_key_path }}".strip()
CC_HOST_CRT_PATH = "{{ cookiecutter.ssl_host_crt_path }}".strip()
# new ca will be created into if CC_GENERATE_CA is "yes"
CC_GENERATE_CA = "{{ cookiecutter.ssl_generate_ca }}".strip().upper()
# crt and key file paths,
# if CC_GENERATE_CA is yes then these should not exist else error
# if CC_GENERATE_CA is not yes, these these should both exist in pem format
CC_CA_CRT_PATH = "{{ cookiecutter.ssl_ca_crt_path }}".strip()
CC_CA_KEY_PATH = "{{ cookiecutter.ssl_ca_key_path }}".strip()
CWD = os.getcwd()
SSLDIR = os.path.join( CWD, "ssl" )
CERTSDIR = os.path.join( CWD, "certs" )
OPENRESTYSSLDIR = os.path.join( CWD, "openresty", "openresty", "ssl" )
HOST_CSR_PATH = os.path.join( SSLDIR, "gen", "host.csr" )
HOST_EXT_FILE = os.path.join( SSLDIR, "host_ext.conf" )
FINAL_HOST_CRT_PATH = os.path.join( CERTSDIR, "tls.crt" )
FINAL_HOST_KEY_PATH = os.path.join( CERTSDIR, "tls.key" )
FINAL_CA_CRT_PATH = os.path.join( CERTSDIR, "ca.crt" )
FINAL_DHPARAM_PATH = os.path.join( OPENRESTYSSLDIR, "dhparam.pem" )

def log( msg ):
    print( "{}: {}".format( PROGRAM_NAME, msg ) )

def run( *args ):
    proc = subprocess.Popen( args )
    proc.wait()
    return proc.returncode

def main():
    final_host_key_exists = os.path.isfile( FINAL_HOST_KEY_PATH )
    final_host_crt_exists = os.path.isfile( FINAL_HOST_CRT_PATH )
    final_ca_crt_exists = os.path.isfile( FINAL_CA_CRT_PATH )
    final_dhparam_exists = os.path.isfile( FINAL_DHPARAM_PATH )

    ################################################
    # generate dhparam if it does not exist
    ################################################
    if not final_dhparam_exists:
        log( "generating dhparam ..." )
        rc = run( "openssl", "dhparam", "-out", FINAL_DHPARAM_PATH, "2048" )
        final_dhparam_exists = os.path.isfile( FINAL_DHPARAM_PATH )
        if rc != 0 or not final_dhparam_exists:
            log( "failed to generate dhparam" )
            return -4

    if final_host_key_exists or final_host_crt_exists or final_ca_crt_exists:
        log( "final files exist" )
        return -3

    host_key_exists = os.path.isfile( CC_HOST_KEY_PATH )
    host_crt_exists = os.path.isfile( CC_HOST_CRT_PATH )
    host_csr_exists = os.path.isfile( HOST_CSR_PATH )
    ca_crt_exists = os.path.isfile( CC_CA_CRT_PATH )
    need_gen_host_crt = False

    if CC_GENERATE_HOST_KEYCSR != "YES" and CC_GENERATE_CA == "YES" and not host_csr_exists:
        log( "generating ca without generating host csr and host csr does not already exist" )
        return -2
        
    if host_key_exists and host_crt_exists and not ca_crt_exists:
        log( "host key and host crt already exist but no signing ca provided" )
        return -1

    ################################################
    # generate host key and csr if they do not exist
    # openssl genrsa -out host.key 2048
    # openssl req -new -key host.key -out host.csr
    ################################################
    if CC_GENERATE_HOST_KEYCSR == "YES":
        # 1) generate host key if one was not provided
        if not host_key_exists:
            log( "generating host key ..." )
            rc = run( "openssl", "genrsa", "-out", CC_HOST_KEY_PATH, "2048" )
            host_key_exists = os.path.isfile( CC_HOST_KEY_PATH )
            if rc != 0 or not host_key_exists:
                log( "failed to generate host key" )
                return 2
        # 2) generate host csr
        if not host_csr_exists:
            log( "generating host csr ..." )
            rc = run( "openssl", "req", "-new", \
                      "-key", CC_HOST_KEY_PATH, "-out", HOST_CSR_PATH )
            host_csr_exists = os.path.isfile( HOST_CSR_PATH )
            if rc != 0 or not host_csr_exists:
                log( "failed to generate host csr" )
                return 3
        need_gen_host_crt = True
    elif not host_csr_exists or not host_crt_exists:
        log( "host csr or host crt does not exist" )
        return 4

    ################################################
    # generate ca if ca key and crt do not exist
    # openssl genrsa -des3 -out myCA.key 2048
    # openssl req -x509 -new -nodes -key myCA.key -sha256 -days 1825 -out myCA.pem
    ################################################
    ca_key_exists = os.path.isfile( CC_CA_KEY_PATH )
    if CC_GENERATE_CA == "YES":
        # 1) generate ca key if one was not provided
        if not ca_key_exists:
            log( "generating ca key ..." )
            rc = run( "openssl", "genrsa", "-des3", "-out", CC_CA_KEY_PATH, "2048" )
            ca_key_exists = os.path.isfile( CC_CA_KEY_PATH )
            if rc != 0 or not ca_key_exists:
                log( "failed to generate ca key" )
                return 6

        # 2) generate ca crt
        if not ca_crt_exists:
            log( "generating ca selfsigned crt ..." )
            rc = run( "openssl", "req", "-x509", "-new", "-nodes", \
                      "-key", CC_CA_KEY_PATH, "-sha256", "-days", "1825", "-out", CC_CA_CRT_PATH )
            ca_crt_exists = os.path.isfile( CC_CA_CRT_PATH )
            if rc != 0 or not ca_crt_exists:
                log( "failed to generate ca crt" )
                return 7
        need_gen_host_crt = True
    else:
        if need_gen_host_crt and not ca_key_exists:
            log( "host crt must be generated by ca key does not exist" )
            return 8
        if not ca_crt_exists:
            log( "ca crt does not exist" )
            return 9

    ################################################
    # generate host crt using host csr, ca crt and ca key
    # openssl x509 -req -in host.csr -CA myCA.pem -CAkey myCA.key -CAcreateserial
    # -out host.crt -days 365 -sha256 -extfile host_ext.conf
    ################################################
    if need_gen_host_crt:
        # 1) generate host crt
        log( "generating host crt ..." )
        rc = run( "openssl", "x509", "-req", "-in", HOST_CSR_PATH, \
                  "-CA", CC_CA_CRT_PATH, "-CAkey", CC_CA_KEY_PATH, "-CAcreateserial", \
                  "-out", CC_HOST_CRT_PATH, "-days", "{{ cookiecutter.ssl_host_crt_days }}", \
                  "-sha256", "-extfile", HOST_EXT_FILE )
        host_crt_exists = os.path.isfile( CC_HOST_CRT_PATH )
        if rc != 0 or not host_crt_exists:
            log( "failed to generate host crt" )
            return 10
        # 2) verify host crt w.r.t. ca crt
        rc = run( "openssl", "verify", "-CAfile", CC_CA_CRT_PATH, CC_HOST_CRT_PATH )
        if rc != 0:
            log( "failed to verify host crt" )
            return 11

    ################################################
    # copy files to their final locations
    ################################################
    shutil.copyfile( CC_HOST_KEY_PATH, FINAL_HOST_KEY_PATH )
    shutil.copyfile( CC_HOST_CRT_PATH, FINAL_HOST_CRT_PATH )
    shutil.copyfile( CC_CA_CRT_PATH, FINAL_CA_CRT_PATH )

    return 0

if __name__ == '__main__':
    ret = main()
    sys.exit( ret )
