#include "req.h"





size_t req_write_callback(void *data, size_t size, size_t nmemb, void *clientp){

    size_t realsize = size * nmemb;

    memcpy(clientp, data, realsize);

    return realsize;
}


int request_get(char* result, char* req_url){


    CURL *curl;
    CURLcode res;


    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, req_url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, req_write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, result);
        res = curl_easy_perform(curl);
        if(res != CURLE_OK){
            fprintf(stderr, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        }
        curl_easy_cleanup(curl);

    } else {
        strcpy(result, "curl init failed");
        return -1;
    }

    return 0;

}

int request_post(char* result, char* req_url, char* payload){

    //const char* c_req_url = req_url.c_str();

    CURL *curl;
    CURLcode res;

    curl = curl_easy_init();

    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, req_url);
        curl_easy_setopt(curl,CURLOPT_POSTFIELDS, payload);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, req_write_callback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void*)result);
        res = curl_easy_perform(curl);
        if(res != CURLE_OK){
            fprintf(stderr, "curl_easy_perform() failed: %s\n",curl_easy_strerror(res));
        }
        curl_easy_cleanup(curl);

    } else {
        strcpy(result,"curl init failed");
        return -1;
    }


    return 0;
}





int main(int argc, char** argv){


    char result[10240] = {0};


    char* get_url = "https://ipinfo.io/ip";


    char* post_url = "https://www.postb.in/1724202597872-6274518070276";


    char post_payload[1024] = {0};

    sprintf(post_payload, "%s=%s&%s=%s", "test", "yes", "req", "hello");

    printf("sending GET: \n");

    int resp = request_get(result, get_url);

    if(resp < 0){

        printf("failed to GET: %d\n", resp);

        return -1;
    }

    printf("%s\n", result);

    memset(result, 0, 10240);

    printf("sending POST: \n");

    resp = request_post(result, post_url, post_payload);

    if (resp < 0){

        printf("failed to POST: %d\n", resp);

        return -1;
    }

    printf("%s\n", result);


    return 0;


}