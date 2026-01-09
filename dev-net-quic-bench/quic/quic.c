
#include "quic.h"


QUIC_REGISTRATION_CONFIG quic_reg_config = { "quicsample", QUIC_EXECUTION_PROFILE_LOW_LATENCY };

QUIC_BUFFER quic_alpn = { sizeof("sample") - 1, (uint8_t*)"sample" };

uint16_t quic_udp_port = SERVER_PORT;

uint64_t quic_idle_timeoutms = 1000;

uint32_t quic_send_buffer_len = INPUT_BUFF_CHUNK;

QUIC_API_TABLE* quic_api;


HQUIC quic_registration;


HQUIC quic_configuration;

QUIC_TLS_SECRETS quic_client_secrets = {0};



pthread_t client_tid;
pthread_t server_tid;
uint64_t client_total_sent = 0;
#if DATA_VALIDITY_CHECK
uint8_t server_total_data[INPUT_BUFF_MAX] = {0};
#endif
uint64_t server_total_recvd = 0;
uint64_t server_this_recvd = 0;
uint32_t this_chunk = 0;
uint8_t* server_buffer_raw;
QUIC_BUFFER* server_buffer_ack;
char* server_ack = "ack";
int server_done = 0;
int client_stream_ack = 0;
int client_done = 0;
struct timeval t1, t2;


void* server_complete(void* varg){

#if DATA_VALIDITY_CHECK
    int total_chunks = INPUT_BUFF_MAX / INPUT_BUFF_CHUNK;

    int bound = INPUT_BUFF_CHUNK / 4;

    int invalid = 0;

    for(int i = 0; i < total_chunks; i++){

        for(int j = (i * INPUT_BUFF_CHUNK) ; j < ((i + 1 ) * INPUT_BUFF_CHUNK); j++){

            if(j < ((i * INPUT_BUFF_CHUNK) + (bound * 1))){
                if(server_total_data[j] != 'a'){
                    invalid = 1;
                    printf("invalid data at: %d: %c(a)\n", j, server_total_data[j]);

                }
            } else if(j < ((i * INPUT_BUFF_CHUNK) + (bound * 2))){
                if(server_total_data[j] != 'b'){
                    invalid = 1;
                    printf("invalid data at: %d: %c(b)\n", j, server_total_data[j]);                

                }
            } else if(j < ((i * INPUT_BUFF_CHUNK) + (bound * 3))){
                if(server_total_data[j] != 'c'){
                    invalid = 1;
                    printf("invalid data at: %d: %c(c)\n", j, server_total_data[j]);                

                }
            } else if(j < ((i * INPUT_BUFF_CHUNK) + (bound * 4))){
                if(server_total_data[j] != 'd'){
                    invalid = 1;
                    printf("invalid data at: %d: %c(d)\n", j, server_total_data[j]);                

                }
            } 

        }
        if(invalid){
            break;
        }
    }
    if(!invalid){
        printf("all data is valid\n");
    }
#endif
    server_done = 1;

    pthread_exit(NULL);
}


void server_send_ack(HQUIC stream){
#if ACK_CHECK
    QUIC_STATUS status;

    if (QUIC_FAILED(status = quic_api->StreamSend(stream, server_buffer_ack, 1, QUIC_SEND_FLAG_NONE, server_buffer_ack))) {
        printf("server StreamSend failed, 0x%x!\n", status);
        return;
    }
#endif
}

void server_recv(QUIC_BUFFER* qbuff, uint32_t buff_count, uint64_t buff_tot_len, HQUIC stream){


    server_total_recvd += buff_tot_len;
    for(int i = 0 ; i < buff_count; i++){
#if DATA_VALIDITY_CHECK
        memcpy(server_total_data + server_this_recvd, qbuff[i].Buffer, qbuff[i].Length);      
#endif
        server_this_recvd += qbuff[i].Length;
    }



    if(server_this_recvd >= INPUT_BUFF_MAX){
        gettimeofday(&t2, NULL);
        server_send_ack(stream);
        uint32_t seconds = t2.tv_sec - t1.tv_sec;      
        int ms = (t2.tv_usec - t1.tv_usec) / 1000;
        if(ms < 0){
            ms = ms * -1;
        }
        printf("sec: %u ms: %d\n", seconds, ms);
        printf("server recvd total: %lu\n", server_this_recvd);
        server_this_recvd = 0;
    }

    return;

}

QUIC_STATUS server_stream_cb(HQUIC stream, void* context, QUIC_STREAM_EVENT* event){

    UNREFERENCED_PARAMETER(context);
    switch (event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        //free(event->SEND_COMPLETE.ClientContext);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        server_recv(event->RECEIVE.Buffers, event->RECEIVE.BufferCount, event->RECEIVE.TotalBufferLength, stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        printf("client shut down\n");
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        printf("client aborted\n");
        quic_api->StreamShutdown(stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        printf("stream done\n");
        quic_api->StreamClose(stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS server_conn_cb(HQUIC connection,void* context, QUIC_CONNECTION_EVENT* event){

    UNREFERENCED_PARAMETER(context);
    switch (event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:

        printf("client connected\n");
        server_buffer_raw = (uint8_t*)malloc(sizeof(QUIC_BUFFER) + 4);
        if (server_buffer_raw == NULL) {
            printf("server SendBuffer allocation failed!\n");
            return -1;
        }
        server_buffer_ack = (QUIC_BUFFER*)server_buffer_raw;
        server_buffer_ack->Buffer = server_buffer_raw + sizeof(QUIC_BUFFER);
        server_buffer_ack->Length = 4;
        strcpy((char*)server_buffer_ack->Buffer, server_ack);

        gettimeofday(&t1, NULL);
        quic_api->ConnectionSendResumptionTicket(connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        if (event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
            printf("successfully shut down on idle\n");
        } else {
            printf("shut down by transport: 0x%x\n", event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        printf("shut down by peer: 0x%llu\n",(unsigned long long)event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("connection done\n");
        pthread_create(&server_tid, NULL, server_complete, NULL);
        quic_api->ConnectionClose(connection);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        printf("client stream started\n");
        quic_api->SetCallbackHandler(event->PEER_STREAM_STARTED.Stream, (void*)server_stream_cb, NULL);
        break;
    case QUIC_CONNECTION_EVENT_RESUMED:
        printf("client connection resumed\n");
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS server_listen_cb(HQUIC listener, void* context, QUIC_LISTENER_EVENT* event){

    UNREFERENCED_PARAMETER(listener);
    UNREFERENCED_PARAMETER(context);
    QUIC_STATUS status = QUIC_STATUS_NOT_SUPPORTED;
    switch (event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        quic_api->SetCallbackHandler(event->NEW_CONNECTION.Connection, (void*)server_conn_cb, NULL);
        status = quic_api->ConnectionSetConfiguration(event->NEW_CONNECTION.Connection, quic_configuration);
        break;
    default:
        break;
    }
    return status;
}



int server_conf() {

    QUIC_SETTINGS settings = {0};

    settings.IdleTimeoutMs = quic_idle_timeoutms;
    settings.IsSet.IdleTimeoutMs = TRUE;

    settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    settings.IsSet.ServerResumptionLevel = TRUE;

    settings.PeerBidiStreamCount = 1;
    settings.IsSet.PeerBidiStreamCount = TRUE;

    QUIC_CREDENTIAL_CONFIG_HELPER config;
    memset(&config, 0, sizeof(config));
    config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;
    config.CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;
    config.CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES;
    config.CredConfig.AllowedCipherSuites = QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384;


    const char* ca = CERT_CA;
    const char* cert = CERT_SERVER;
    const char* key = KEY_SERVER;

    config.CertFile.CertificateFile = (char*)cert;
    config.CertFile.PrivateKeyFile = (char*)key;
    config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    config.CredConfig.CertificateFile = &config.CertFile;
    config.CredConfig.CaCertificateFile = ca;

    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(status = quic_api->ConfigurationOpen(quic_registration, &quic_alpn, 1, &settings, sizeof(settings), NULL, &quic_configuration))) {
        printf("ConfigurationOpen failed, 0x%x!\n", status);
        return FALSE;
    }

    if (QUIC_FAILED(status = quic_api->ConfigurationLoadCredential(quic_configuration, &config.CredConfig))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", status);
        return FALSE;
    }

    return TRUE;
}


void run_server(){
    QUIC_STATUS status;
    HQUIC listener = NULL;

    QUIC_ADDR address = {0};
    QuicAddrSetFamily(&address, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&address, quic_udp_port);

    if (server_conf() < 0) {
        return;
    }

    if (QUIC_FAILED(status = quic_api->ListenerOpen(quic_registration, server_listen_cb, NULL, &listener))) {
        printf("ListenerOpen failed, 0x%x!\n", status);
        goto error;
    }


    if (QUIC_FAILED(status = quic_api->ListenerStart(listener, &quic_alpn, 1, &address))) {
        printf("ListenerStart failed, 0x%x!\n", status);
        goto error;
    }

    while(!server_done){
        sleep(1);
    }

error:

    if (listener != NULL) {
        quic_api->ListenerClose(listener);
    }
}




QUIC_STATUS client_stream_cb(HQUIC stream, void* context, QUIC_STREAM_EVENT* event){

    UNREFERENCED_PARAMETER(context);
    switch (event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:

        //free(Event->SEND_COMPLETE.ClientContext);

        break;
    case QUIC_STREAM_EVENT_RECEIVE:

        if(strcmp((char*)event->RECEIVE.Buffers[0].Buffer, server_ack) == 0){
            client_stream_ack = 1;
        }

        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:

        printf("server aborted\n");
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        printf("server shut down\n");
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        printf("stream done\n");
        if (!event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            quic_api->StreamClose(stream);
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void client_recv_ack(){
#if ACK_CHECK        
    do{usleep(1);}while(!client_stream_ack);
    client_stream_ack = 0;
#endif     
}

void* client_send(void* varg){

    HQUIC connection = (HQUIC)varg;
    QUIC_STATUS status;
    HQUIC stream = NULL;
    uint8_t* send_buffer_raw = NULL;
    QUIC_BUFFER* send_buffer;

    if (QUIC_FAILED(status = quic_api->StreamOpen(connection, QUIC_STREAM_OPEN_FLAG_NONE, client_stream_cb, NULL, &stream))) {
        printf("StreamOpen failed, 0x%x!\n", status);
        goto error;
    }

    if (QUIC_FAILED(status = quic_api->StreamStart(stream, QUIC_STREAM_START_FLAG_NONE))) {
        printf("StreamStart failed, 0x%x!\n", status);
        quic_api->StreamClose(stream);
        goto error;
    }

    send_buffer_raw = (uint8_t*)malloc(sizeof(QUIC_BUFFER) + quic_send_buffer_len);
    if (send_buffer_raw == NULL) {
        printf("SendBuffer allocation failed!\n");
        status = QUIC_STATUS_OUT_OF_MEMORY;
        goto error;
    }


    send_buffer = (QUIC_BUFFER*)send_buffer_raw;
    send_buffer->Buffer = send_buffer_raw + sizeof(QUIC_BUFFER);
    send_buffer->Length = quic_send_buffer_len;

#if DATA_VALIDITY_CHECK
    uint8_t* sb_fill = NULL;
    int bound = INPUT_BUFF_CHUNK / 4;

    for(int i = 0 ; i < INPUT_BUFF_CHUNK; i++){
        
        sb_fill = send_buffer->Buffer + i;

        if(i < (bound * 1)){
            *sb_fill = 'a';
        } else if(i < (bound * 2)){
            *sb_fill = 'b';
        } else if(i < (bound * 3)){
            *sb_fill = 'c';
        } else if(i < (bound * 4)){
            *sb_fill = 'd';
        } 


    }
#endif

    printf("client sending...\n");

    for(;;){
#if !DATA_VALIDITY_CHECK         
        if(getrandom(send_buffer->Buffer, quic_send_buffer_len, 0) < 0){
            printf("getrandom failed\n");
            goto error;
        }
#endif        
        
        if (QUIC_FAILED(status = quic_api->StreamSend(stream, send_buffer, 1, QUIC_SEND_FLAG_NONE, send_buffer))) {
            printf("StreamSend failed, 0x%x!\n", status);
            free(send_buffer_raw);
            goto error;
        }
    
        client_total_sent += quic_send_buffer_len;
        if(client_total_sent >= INPUT_BUFF_MAX){
            client_recv_ack();
            send_buffer->Length = 0;
            if (QUIC_FAILED(status = quic_api->StreamSend(stream, send_buffer, 1, QUIC_SEND_FLAG_FIN, send_buffer))) {
                printf("StreamSend failed, 0x%x!\n", status);
                free(send_buffer_raw);
                goto error;
            }
            printf("client send done\n");
            break;
        }


    }
    printf("client sent total: %lu\n", client_total_sent);

    
error:

    if (QUIC_FAILED(status)) {
        quic_api->ConnectionShutdown(connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    }

    /*
    if(send_buffer_raw != NULL){
        free(send_buffer_raw);
    }
        */

    pthread_exit(NULL);
}

QUIC_STATUS client_conn_cb(HQUIC connection, void* context, QUIC_CONNECTION_EVENT* event){

    UNREFERENCED_PARAMETER(context);

    if (event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {

        printf("client: quic event connected\n");
    }

    switch (event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        printf("connected\n");
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        if (event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
            printf("successfully shut down on idle\n");
        } else {
            printf("shut down by transport: 0x%x\n", event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:

        printf("shut down by server: 0x%llu\n",(unsigned long long)event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:

        printf("connection done\n");
        if (!event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            quic_api->ConnectionClose(connection);
        }
        client_done = 1;
        break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        printf("resumption ticket received: %u bytes\n", event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
        pthread_create(&client_tid, NULL, client_send, (void*)connection);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}


int client_conf(){
    QUIC_SETTINGS settings = {0};

    settings.IdleTimeoutMs = quic_idle_timeoutms;
    settings.IsSet.IdleTimeoutMs = TRUE;

    QUIC_CREDENTIAL_CONFIG config;
    memset(&config, 0, sizeof(config));
    config.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    config.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    config.Flags |= QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;
    config.Flags |= QUIC_CREDENTIAL_FLAG_SET_ALLOWED_CIPHER_SUITES;
    config.AllowedCipherSuites = QUIC_ALLOWED_CIPHER_SUITE_AES_256_GCM_SHA384;

    const char* ca = CERT_CA;
    const char* cert = CERT_CLIENT;
    const char* key = KEY_CLIENT;

    QUIC_CERTIFICATE_FILE cert_file;    
    cert_file.CertificateFile = (char*)cert;
    cert_file.PrivateKeyFile = (char*)key;
    config.CertificateFile = &cert_file;
    config.CaCertificateFile = ca;


    QUIC_STATUS status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(status = quic_api->ConfigurationOpen(quic_registration, &quic_alpn, 1, &settings, sizeof(settings), NULL, &quic_configuration))) {
        printf("ConfigurationOpen failed, 0x%x!\n", status);
        return -1;
    }

    if (QUIC_FAILED(status = quic_api->ConfigurationLoadCredential(quic_configuration, &config))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", status);
        return -1;
    }

    return 0;
}

void run_client() {

    if (client_conf() < 0) {
        return;
    }

    QUIC_STATUS status;
    //const char* resumption_ticket_string = NULL;

    HQUIC connection = NULL;

    if (QUIC_FAILED(status = quic_api->ConnectionOpen(quic_registration, client_conn_cb, NULL, &connection))) {
        printf("ConnectionOpen failed, 0x%x!\n", status);
        goto error;
    }

    const char* target = SERVER_ADDR;

    if (QUIC_FAILED(status = quic_api->ConnectionStart(connection, quic_configuration, QUIC_ADDRESS_FAMILY_UNSPEC, target, quic_udp_port))) {
        printf("ConnectionStart failed, 0x%x!\n", status);
        goto error;
    }

    while(!client_done){
        sleep(1);
    }


error:

    if (QUIC_FAILED(status) && connection != NULL) {
        quic_api->ConnectionClose(connection);
    }
}

static void help(){

    printf("option: [c|s]\n");
    printf("c: client mode\n");
    printf("s: server mode\n");
}



int main(int argc, char** argv){

    if(argc != 2){
        help();
        return -1;
    }

    QUIC_STATUS status = QUIC_STATUS_SUCCESS;

    if (QUIC_FAILED(status = MsQuicOpen2(&quic_api))) {
        printf("MsQuicOpen2 failed, 0x%x!\n", status);
        goto error;
    }

    if (QUIC_FAILED(status = quic_api->RegistrationOpen(&quic_reg_config, &quic_registration))) {
        printf("RegistrationOpen failed, 0x%x!\n", status);
        goto error;
    }

    if(strcmp(argv[1], "c") == 0){
        run_client();
    } else if(strcmp(argv[1], "s") == 0){
        run_server();
    } else {
        help();
        goto error;
    }

error:

    if (quic_api != NULL) {
        if (quic_configuration != NULL) {
            quic_api->ConfigurationClose(quic_configuration);
        }
        if (quic_registration != NULL) {
            quic_api->RegistrationClose(quic_registration);
        }
        MsQuicClose(quic_api);
    }

    return (int)status;
}