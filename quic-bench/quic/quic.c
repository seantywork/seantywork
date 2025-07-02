
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
uint32_t client_total_sent = 0;
uint8_t server_total_data[INPUT_BUFF_CHUNK] = {0};
uint32_t server_total_recvd = 0;


void server_recv(QUIC_BUFFER* qbuff){

    //memcpy(server_total_data, qbuff->Buffer, qbuff->Length);

    server_total_recvd += qbuff->Length;    

    printf("server this buffer length: %lu\n", qbuff->Length);
    printf("server total buff count: %lu\n", server_total_recvd);

    return;

}

QUIC_STATUS server_stream_cb(HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event){

    UNREFERENCED_PARAMETER(Context);
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        //
        // A previous StreamSend call has completed, and the context is being
        // returned back to the app.
        //
        free(Event->SEND_COMPLETE.ClientContext);
        printf("[strm][%p] Data sent\n", Stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        //
        // Data was received from the peer on the stream.
        //

        server_recv(Event->RECEIVE.Buffers);

        printf("[strm][%p] Data received\n", Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //
        // The peer gracefully shut down its send direction of the stream.
        //
        printf("[strm][%p] Peer shut down\n", Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // The peer aborted its send direction of the stream.
        //
        printf("[strm][%p] Peer aborted\n", Stream);
        quic_api->StreamShutdown(Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT, 0);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //
        // Both directions of the stream have been shut down and quic_api is done
        // with the stream. It can now be safely cleaned up.
        //

        printf("[strm][%p] All done\n", Stream);
        quic_api->StreamClose(Stream);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

//
// The server's callback for connection events from quic_api.
//
QUIC_STATUS server_conn_cb(HQUIC Connection,void* Context, QUIC_CONNECTION_EVENT* Event){

    UNREFERENCED_PARAMETER(Context);
    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //
        // The handshake has completed for the connection.
        //
        printf("[conn][%p] Connected\n", Connection);
        quic_api->ConnectionSendResumptionTicket(Connection, QUIC_SEND_RESUMPTION_FLAG_NONE, 0, NULL);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //
        // The connection has been shut down by the transport. Generally, this
        // is the expected way for the connection to shut down with this
        // protocol, since we let idle timeout kill the connection.
        //
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
            printf("[conn][%p] Successfully shut down on idle.\n", Connection);
        } else {
            printf("[conn][%p] Shut down by transport, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        //
        // The connection was explicitly shut down by the peer.
        //
        printf("[conn][%p] Shut down by peer, 0x%llu\n", Connection, (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //
        // The connection has completed the shutdown process and is ready to be
        // safely cleaned up.
        //
        printf("[conn][%p] All done\n", Connection);
        quic_api->ConnectionClose(Connection);
        break;
    case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED:
        //
        // The peer has started/created a new stream. The app MUST set the
        // callback handler before returning.
        //
        printf("[strm][%p] Peer started\n", Event->PEER_STREAM_STARTED.Stream);
        quic_api->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream, (void*)server_stream_cb, NULL);
        break;
    case QUIC_CONNECTION_EVENT_RESUMED:
        //
        // The connection succeeded in doing a TLS resumption of a previous
        // connection's session.
        //
        printf("[conn][%p] Connection resumed!\n", Connection);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

//
// The server's callback for listener events from quic_api.
//

QUIC_STATUS server_listen_cb(HQUIC Listener, void* Context, QUIC_LISTENER_EVENT* Event){

    UNREFERENCED_PARAMETER(Listener);
    UNREFERENCED_PARAMETER(Context);
    QUIC_STATUS Status = QUIC_STATUS_NOT_SUPPORTED;
    switch (Event->Type) {
    case QUIC_LISTENER_EVENT_NEW_CONNECTION:
        //
        // A new connection is being attempted by a client. For the handshake to
        // proceed, the server must provide a configuration for QUIC to use. The
        // app MUST set the callback handler before returning.
        //
        quic_api->SetCallbackHandler(Event->NEW_CONNECTION.Connection, (void*)server_conn_cb, NULL);
        Status = quic_api->ConnectionSetConfiguration(Event->NEW_CONNECTION.Connection, quic_configuration);
        break;
    default:
        break;
    }
    return Status;
}


//
// Helper function to load a server configuration. Uses the command line
// arguments to load the credential part of the configuration.
//
BOOLEAN server_conf() {

    QUIC_SETTINGS Settings = {0};
    //
    // Configures the server's idle timeout.
    //
    Settings.IdleTimeoutMs = quic_idle_timeoutms;
    Settings.IsSet.IdleTimeoutMs = TRUE;
    //
    // Configures the server's resumption level to allow for resumption and
    // 0-RTT.
    //
    Settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    Settings.IsSet.ServerResumptionLevel = TRUE;
    //
    // Configures the server's settings to allow for the peer to open a single
    // bidirectional stream. By default connections are not configured to allow
    // any streams from the peer.
    //
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
  //
    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.
    //
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = quic_api->ConfigurationOpen(quic_registration, &quic_alpn, 1, &Settings, sizeof(Settings), NULL, &quic_configuration))) {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    //
    // Loads the TLS credential part of the configuration.
    //
    if (QUIC_FAILED(Status = quic_api->ConfigurationLoadCredential(quic_configuration, &Config.CredConfig))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }

    return TRUE;
}

//
// Runs the server side of the protocol.
//
void run_server(){
    QUIC_STATUS Status;
    HQUIC Listener = NULL;

    //
    // Configures the address used for the listener to listen on all IP
    // addresses and the given UDP port.
    //
    QUIC_ADDR Address = {0};
    QuicAddrSetFamily(&Address, QUIC_ADDRESS_FAMILY_UNSPEC);
    QuicAddrSetPort(&Address, quic_udp_port);

    //
    // Load the server configuration based on the command line.
    //
    if (!server_conf()) {
        return;
    }

    //
    // Create/allocate a new listener object.
    //
    if (QUIC_FAILED(Status = quic_api->ListenerOpen(quic_registration, server_listen_cb, NULL, &Listener))) {
        printf("ListenerOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    //
    // Starts listening for incoming connections.
    //
    if (QUIC_FAILED(Status = quic_api->ListenerStart(Listener, &quic_alpn, 1, &Address))) {
        printf("ListenerStart failed, 0x%x!\n", Status);
        goto Error;
    }

    //
    // Continue listening for connections until the Enter key is pressed.
    //
    printf("Press Enter to exit.\n\n");
    getchar();

Error:

    if (Listener != NULL) {
        quic_api->ListenerClose(Listener);
    }
}




QUIC_STATUS client_stream_cb(HQUIC Stream, void* Context, QUIC_STREAM_EVENT* Event){

    UNREFERENCED_PARAMETER(Context);
    switch (Event->Type) {
    case QUIC_STREAM_EVENT_SEND_COMPLETE:
        //
        // A previous StreamSend call has completed, and the context is being
        // returned back to the app.
        //
        //free(Event->SEND_COMPLETE.ClientContext);
        //printf("[strm][%p] Data sent\n", Stream);
        break;
    case QUIC_STREAM_EVENT_RECEIVE:
        //
        // Data was received from the peer on the stream.
        //
        printf("[strm][%p] Data received\n", Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        //
        // The peer gracefully shut down its send direction of the stream.
        //
        printf("[strm][%p] Peer aborted\n", Stream);
        break;
    case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        //
        // The peer aborted its send direction of the stream.
        //
        printf("[strm][%p] Peer shut down\n", Stream);
        break;
    case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
        //
        // Both directions of the stream have been shut down and quic_api is done
        // with the stream. It can now be safely cleaned up.
        //
        printf("[strm][%p] All done\n", Stream);
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
    uint8_t* SendBufferRaw;
    uint8_t* sb_fill = NULL;
    QUIC_BUFFER* SendBuffer;

    //
    // Create/allocate a new bidirectional stream. The stream is just allocated
    // and no QUIC stream identifier is assigned until it's started.
    //
    if (QUIC_FAILED(Status = quic_api->StreamOpen(Connection, QUIC_STREAM_OPEN_FLAG_NONE, client_stream_cb, NULL, &Stream))) {
        printf("StreamOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    printf("[strm][%p] Starting...\n", Stream);

    //
    // Starts the bidirectional stream. By default, the peer is not notified of
    // the stream being started until data is sent on the stream.
    //
    if (QUIC_FAILED(Status = quic_api->StreamStart(Stream, QUIC_STREAM_START_FLAG_NONE))) {
        printf("StreamStart failed, 0x%x!\n", Status);
        quic_api->StreamClose(Stream);
        goto Error;
    }

    //
    // Allocates and builds the buffer to send over the stream.
    //
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
    printf("[strm][%p] Sending data...\n", Stream);

    //
    // Sends the buffer over the stream. Note the FIN flag is passed along with
    // the buffer. This indicates this is the last buffer on the stream and the
    // the stream is shut down (in the send direction) immediately after.
    //

    /*
    if(getrandom(SendBuffer->Buffer, quic_send_buffer_len, 0) < 0){
        printf("getrandom failed\n");
        goto Error;
    }
    if (QUIC_FAILED(Status = quic_api->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_FIN, SendBuffer))) {
        printf("StreamSend failed, 0x%x!\n", Status);
        free(SendBufferRaw);
        goto Error;
    }
    */
    
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
        printf("client sent: %lu\n", client_total_sent);
        if(client_total_sent >= INPUT_BUFF_MAX - 1){
            if (QUIC_FAILED(Status = quic_api->StreamSend(Stream, SendBuffer, 1, QUIC_SEND_FLAG_FIN, SendBuffer))) {
                printf("StreamSend failed, 0x%x!\n", Status);
                free(SendBufferRaw);
                goto Error;
            }
            printf("client send done\n");
            break;
        }
    }
        
Error:

    if (QUIC_FAILED(Status)) {
        quic_api->ConnectionShutdown(Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    }

    pthread_exit(NULL);
}

//
// The clients's callback for connection events from quic_api.
//

QUIC_STATUS client_conn_cb(HQUIC Connection, void* Context, QUIC_CONNECTION_EVENT* Event){

    UNREFERENCED_PARAMETER(Context);

    if (Event->Type == QUIC_CONNECTION_EVENT_CONNECTED) {

        printf("client: quic event connected\n");
    }

    switch (Event->Type) {
    case QUIC_CONNECTION_EVENT_CONNECTED:
        //
        // The handshake has completed for the connection.
        //
        printf("[conn][%p] Connected\n", Connection);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        //
        // The connection has been shut down by the transport. Generally, this
        // is the expected way for the connection to shut down with this
        // protocol, since we let idle timeout kill the connection.
        //
        if (Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status == QUIC_STATUS_CONNECTION_IDLE) {
            printf("[conn][%p] Successfully shut down on idle.\n", Connection);
        } else {
            printf("[conn][%p] Shut down by transport, 0x%x\n", Connection, Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status);
        }
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER:
        //
        // The connection was explicitly shut down by the peer.
        //
        printf("[conn][%p] Shut down by peer, 0x%llu\n", Connection, (unsigned long long)Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode);
        break;
    case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE:
        //
        // The connection has completed the shutdown process and is ready to be
        // safely cleaned up.
        //
        printf("[conn][%p] All done\n", Connection);
        if (!Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
            quic_api->ConnectionClose(Connection);
        }
        break;
    case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED:
        //
        // A resumption ticket (also called New Session Ticket or NST) was
        // received from the server.
        //
        printf("[conn][%p] Resumption ticket received (%u bytes)\n", Connection, Event->RESUMPTION_TICKET_RECEIVED.ResumptionTicketLength);
        pthread_create(&client_tid, NULL, client_send, (void*)Connection);
        break;
    default:
        break;
    }
    return QUIC_STATUS_SUCCESS;
}

//
// Helper function to load a client configuration.
//
BOOLEAN client_conf()
{
    QUIC_SETTINGS Settings = {0};
    //
    // Configures the client's idle timeout.
    //
    Settings.IdleTimeoutMs = quic_idle_timeoutms;
    Settings.IsSet.IdleTimeoutMs = TRUE;

    //
    // Configures a default client configuration, optionally disabling
    // server certificate validation.
    //
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

    //
    // Allocate/initialize the configuration object, with the configured ALPN
    // and settings.
    //
    QUIC_STATUS Status = QUIC_STATUS_SUCCESS;
    if (QUIC_FAILED(Status = quic_api->ConfigurationOpen(quic_registration, &quic_alpn, 1, &Settings, sizeof(Settings), NULL, &quic_configuration))) {
        printf("ConfigurationOpen failed, 0x%x!\n", Status);
        return FALSE;
    }

    //
    // Loads the TLS credential part of the configuration. This is required even
    // on client side, to indicate if a certificate is required or not.
    //
    if (QUIC_FAILED(Status = quic_api->ConfigurationLoadCredential(quic_configuration, &Config))) {
        printf("ConfigurationLoadCredential failed, 0x%x!\n", Status);
        return FALSE;
    }

    return TRUE;
}

//
// Runs the client side of the protocol.
//
void run_client() {
    //
    // Load the client configuration based on the "unsecure" command line option.
    //
    if (!client_conf()) {
        return;
    }

    QUIC_STATUS Status;
    const char* ResumptionTicketString = NULL;
    const char* SslKeyLogFile = getenv(quic_ssl_keylog_env);
    HQUIC Connection = NULL;

    //
    // Allocate a new connection object.
    //
    if (QUIC_FAILED(Status = quic_api->ConnectionOpen(quic_registration, client_conn_cb, NULL, &Connection))) {
        printf("ConnectionOpen failed, 0x%x!\n", Status);
        goto Error;
    }

    //
    // Get the target / server name or IP from the command line.
    //
    const char* Target = SERVER_ADDR;

    printf("[conn][%p] Connecting...\n", Connection);

    //
    // Start the connection to the server.
    //
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
            //
            // This will block until all outstanding child objects have been
            // closed.
            //
            quic_api->RegistrationClose(quic_registration);
        }
        MsQuicClose(quic_api);
    }

    return (int)Status;
}