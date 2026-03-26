#ifndef _QS_H_
#define _QS_H_
#include "qs_common.h"


int qs_key_create();
int qs_encap(char* enc_msg_path, char* sec_path);
int qs_decap(char* enc_msg_path, char* sec_path);
int qs_signature();
int oqs_kem();
int oqs_signature();
int qs_cert_create();
int qs_cert_verify();
int qs_tlsnet(const char *sig_name, const char *kem_name, int dtls_flag);

#endif 