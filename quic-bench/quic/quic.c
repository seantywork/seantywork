
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


char* quic_ssl_keylog_env = "SSLKEYLOGFILE";

pthread_t client_tid;
uint64_t client_total_sent = 0;
//uint8_t server_total_data[INPUT_BUFF_MAX + 65536 + 65536] = {0};
uint64_t server_total_recvd = 0;
uint64_t server_this_recvd = 0;
int server_done = 0;


void server_recv(QUIC_BUFFER* qbuff, uint32_t buff_count, uint64_t buff_tot_len){


    //memcpy(server_total_data + server_total_recvd, qbuff->Buffer, qbuff->Length);


    server_total_recvd += buff_tot_len;
    for(int i = 0 ; i < buff_count; i++){
        server_this_recvd += qbuff[i].Length;        

    }

    //printf("server total buff count: %llu\n", server_total_recvd);
    //printf("server this buff count: %llu\n", server_this_recvd);
    return;

}

QUIC_STATUS server_stream_cb(HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event){

    UNREFERENCED_PARAMETER(Context);
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        free(Event->SEND_COMPLETE.ClientContext);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        server_recv(Event->RECEIVE.Buffers, Event->RECEIVE.BufferCount, Event->RECEIVE.TotalBufferLength);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        printf("client shut down\n");
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        printf("client aborted\n");
        quic_api->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        printf("stream done\n");
        quic_api->StreamClose(Stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS server_conn_cb(HQUIC Connection,void* Context, QUIC_CONNECTION_EVENT* Event){

    UNREFERENCED_PARAMETER(Context);
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:

        printf("client connected\n");
        quic_api->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
            printf("successfully shut down on idle\n");
        } else {
            printf("shut down by transport: 0x%x\n", Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        printf("shut down by peer: 0x%llu\n",(unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        printf("connection done\n");
        quic_api->ConnectionClose(Connection);
        server_done = 1;
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        printf("client stream started\n");
        quic_api->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)server_stream_cb, NULL);
        break;
    case QUIC_CONNECTION_EVENT_RESUMED:
        printf("client connection resumed\n");
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS server_listen_cb(HQUIC Listener, void* Context, QUIC_LISTENER_EVENT* Event){

    UNREFERENCED_PARAMETER(Listener);
    UNREFERENCED_PARAMETER(Context);
    QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        quic_api->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)server_conn_cb, NULL);
        Status = quic_api->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, quic_configuration);
        break;
    default:
        break;
    }
    return Status;
}



BOOLEAN server_conf() {

    QUIC_SETTINGS Settings = {0};

    Settings.IdleTimeoutMs = quic_idle_timeoutms;
    Settings.IsSet.IdleTimeoutMs = TRUE;

    Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    Settings.IsSet.ServerResumptionLevel = TRUE;

    Settings.PeerBidiStreamCount = 1;
    Settings.IsSet.PeerBidiStreamCount = TRUE;

    QUIC_CREDENTIAL_CONFIG_HELPER Config;
    memset(&Config, 0, sizeof(Config));
    Config.CredConfig.Flags = QUIC_CREDENTIAL_FLAG_NONE;
    Config.CredConfig.Flags |= QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;

    const char* Ca = CERT_CA;
    const char* Cert = CERT_SERVER;
    const char* KeyFile = KEY_SERVER;

    Config.CertFile.CertificateFile = (char*)Cert;
    Config.CertFile.PrivateKeyFile = (char*)KeyFile;
    Config.CredConfig.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    Config.CredConfig.CertificateFile = &Config.CertFile;
    Config.CredConfig.CaCertificateFile = Ca;

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = quic_api->ConfigurationOpen(quic_registration, &quic_alpn, 1, &Settings, sizeof(Settings), NULL, &quic_configuration))) {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    if (QUIC_FAILED(Status = quic_api->ConfigurationLoadCredential(quic_configuration, &Config.CredConfig))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }

    return TRUE;
}


void run_server(){
    QUIC_STATUS Status;
    HQUIC Listener = NULL;

    QUIC_ADDR Address = {0};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&Address, quic_udp_port);

    if (!server_conf()) {
        return;
    }

    if (QUIC_FAILED(Status = quic_api->ListenerOpen(quic_registration, server_listen_cb, NULL, &Listener))) {
        printf("ListenerOpen failed, 0x%x!\n", Status);
        goto Error;
    }


    if (QUIC_FAILED(Status = quic_api->ListenerStart(Listener, &quic_alpn, 1, &Address))) {
        printf("ListenerStart failed, 0x%x!\n", Status);
        goto Error;
    }

    while(!server_done){
        sleep(1);
    }

Error:

    if (Listener != NULL) {
        quic_api->ListenerClose(Listener);
    }
}




QUIC_STATUS client_stream_cb(HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event){

    UNREFERENCED_PARAMETER(Context);
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:

        //free(Event->SEND_COMPLETE.ClientContext);

        break;
    case QUIC_STREAM_EVENT_RECEIVE:

        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:

        printf("server aborted\n");
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        printf("server shut down\n");
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        printf("stream done\n");
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            quic_api->StreamClose(Stream);
        }
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

void* client_send(void* varg){

    HQUIC Connection = (HQUIC)varg;
    QUIC_STATUS Status;
    HQUIC Stream = NULL;
    uint8_t* SendBufferRaw = NULL;
    uint8_t* sb_fill = NULL;
    QUIC_BUFFER* SendBuffer;

    if (QUIC_FAILED(Status = quic_api->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE, client_stream_cb, NULL, &Stream))) {
        printf("StreamOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = quic_api->StreamStart(Stream, QUIC_STREAM_START_FLAG_NONE))) {
        printf("StreamStart failed, 0x%x!\n", Status);
        quic_api->StreamClose(Stream);
        goto Error;
    }

    SendBufferRaw = (uint8_t*)malloc(sizeof(QUIC_BUFFER) + quic_send_buffer_len);
    if (SendBufferRaw == NULL) {
        printf("SendBuffer allocation failed!\n");
        Status = QUIC_STATUS_OUT_OF_MEMORY;
        goto Error;
    }


    SendBuffer = (QUIC_BUFFER*)SendBufferRaw;
    SendBuffer->Buffer = SendBufferRaw + sizeof(QUIC_BUFFER);
    SendBuffer->Length = quic_send_buffer_len;

/*
    int bound = INPUT_BUFF_CHUNK / 4;

    for(int i = 0 ; i < INPUT_BUFF_CHUNK; i++){
        
        sb_fill = SendBuffer->Buffer + i;

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
*/

    struct timeval t1, t2;
    gettimeofday(&t1, NULL);

    printf("client sending...\n");

    for(;;){
        if(getrandom(SendBuffer->Buffer, quic_send_buffer_len, 0) < 0){
            printf("getrandom failed\n");
            goto Error;
        }
        if (QUIC_FAILED(Status = quic_api->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_NONE, SendBuffer))) {
            printf("StreamSend failed, 0x%x!\n", Status);
            free(SendBufferRaw);
            goto Error;
        }
        client_total_sent += quic_send_buffer_len;
        //printf("client sent: %lu\n", client_total_sent);
        if(client_total_sent >= INPUT_BUFF_MAX){
            SendBuffer->Length = 0;
            if (QUIC_FAILED(Status = quic_api->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_FIN, SendBuffer))) {
                printf("StreamSend failed, 0x%x!\n", Status);
                free(SendBufferRaw);
                goto Error;
            }
            printf("client send done\n");
            break;
        }
    }
    gettimeofday(&t2, NULL);

    uint32_t seconds = t2.tv_sec - t1.tv_sec;      
    uint32_t ms = (t2.tv_usec - t1.tv_usec) / 1000;
    
    printf("sec: %lu ms: %lu\n", seconds, ms);
        
Error:

    if (QUIC_FAILED(Status)) {
        quic_api->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    }

    if(SendBufferRaw != NULL){
        free(SendBufferRaw);
    }

    pthread_exit(NULL);
}

QUIC_STATUS client_conn_cb(HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event){

    UNREFERENCED_PARAMETER(Context);

    if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {

        printf("client: quic event connected\n");
    }

    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        printf("connected\n");
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
            printf("successfully shut down on idle\n");
        } else {
            printf("shut down by transport: 0x%x\n", Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:

        printf("shut down by server: 0x%llu\n",(unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:

        printf("connection done\n");
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            quic_api->ConnectionClose(Connection);
        }
        break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        printf("resumption ticket received: %u bytes\n", Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
        pthread_create(&client_tid, NULL, client_send, (void*)Connection);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}


BOOLEAN client_conf()
{
    QUIC_SETTINGS Settings = {0};

    Settings.IdleTimeoutMs = quic_idle_timeoutms;
    Settings.IsSet.IdleTimeoutMs = TRUE;

    QUIC_CREDENTIAL_CONFIG Config;
    memset(&Config, 0, sizeof(Config));
    Config.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    Config.Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    Config.Flags |= QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;

    const char* Ca = CERT_CA;
    const char* Cert = CERT_CLIENT;
    const char* Key = KEY_CLIENT;

    QUIC_CERTIFICATE_FILE CertFile;    
    CertFile.CertificateFile = (char*)Cert;
    CertFile.PrivateKeyFile = (char*)Key;
    Config.CertificateFile = &CertFile;
    Config.CaCertificateFile = Ca;


    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = quic_api->ConfigurationOpen(quic_registration, &quic_alpn, 1, &Settings, sizeof(Settings), NULL, &quic_configuration))) {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    if (QUIC_FAILED(Status = quic_api->ConfigurationLoadCredential(quic_configuration, &Config))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }

    return TRUE;
}

void run_client() {

    if (!client_conf()) {
        return;
    }

    QUIC_STATUS Status;
    const char* ResumptionTicketString = NULL;
    const char* SslKeyLogFile = getenv(quic_ssl_keylog_env);
    HQUIC Connection = NULL;

    if (QUIC_FAILED(Status = quic_api->ConnectionOpen(quic_registration, client_conn_cb, NULL, &Connection))) {
        printf("ConnectionOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    const char* Target = SERVER_ADDR;

    if (QUIC_FAILED(Status = quic_api->ConnectionStart(Connection, quic_configuration, QUIC_ADDRESS_FAMILY_UNSPEC, Target, quic_udp_port))) {
        printf("ConnectionStart failed, 0x%x!\n", Status);
        goto Error;
    }

Error:

    if (QUIC_FAILED(Status) && Connection != NULL) {
        quic_api->ConnectionClose(Connection);
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

    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;

    if (QUIC_FAILED(Status = MsQuicOpen2(&quic_api))) {
        printf("MsQuicOpen2 failed, 0x%x!\n", Status);
        goto Error;
    }

    if (QUIC_FAILED(Status = quic_api->RegistrationOpen(&quic_reg_config, &quic_registration))) {
        printf("RegistrationOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    if(strcmp(argv[1], "c") == 0){
        run_client();
    } else if(strcmp(argv[1], "s") == 0){
        run_server();
    } else {
        help();
        return -1;
    }

Error:

    if (quic_api != NULL) {
        if (quic_configuration != NULL) {
            quic_api->ConfigurationClose(quic_configuration);
        }
        if (quic_registration != NULL) {
            quic_api->RegistrationClose(quic_registration);
        }
        MsQuicClose(quic_api);
    }

    return (int)Status;
}