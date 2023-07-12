#include "json.hpp"
#include "yaml/Yaml.cpp"
#include <fstream>

using namespace std;

using json = nlohmann::json;


void Example_UseJsonString(){

    ifstream deployment_string("resource/Deployment.json");
    ifstream deployment_image_pull_secrets_string("resource/Deployment_ImagePullSecrets.json");
    ifstream deployment_containers_string("resource/Deployment_Containers.json");
    ifstream deployment_containers_ports_string("resource/Deployment_Containers_Ports.json");


    json deployment = json::parse(deployment_string);
    json deployment_image_pull_secrets = json::parse(deployment_image_pull_secrets_string);
    json deployment_containers = json::parse(deployment_containers_string);
    json deployment_containers_ports = json::parse(deployment_containers_ports_string);

    
    deployment_containers_ports["containerPort"] = 3306;

    deployment_containers["ports"][0] = deployment_containers_ports;

    deployment_image_pull_secrets["name"] = "test-json-container-secret";

    deployment["spec"]["template"]["spec"]["imagePullSecrets"][0] = deployment_image_pull_secrets;

    deployment["spec"]["template"]["spec"]["containers"][0] = deployment_containers;


    string result = deployment.dump(2);

    cout << result << endl;



}


void Example_UseYamlString(){

    Yaml::Node deployment;
    Yaml::Node deployment_image_pull_secrets;
    Yaml::Node deployment_containers;
    Yaml::Node deployment_containers_ports;

    Yaml::Parse(deployment, "resource/Deployment.yaml");
    Yaml::Parse(deployment_image_pull_secrets,"resource/Deployment_ImagePullSecrets.yaml");
    Yaml::Parse(deployment_containers,"resource/Deployment_Containers.yaml");
    Yaml::Parse(deployment_containers_ports,"resource/Deployment_Containers_Ports.yaml");


    deployment_containers_ports["containerPort"] = "3306";

    deployment_containers["ports"].Insert(0);

    deployment_containers["ports"][0] = deployment_containers_ports;

    deployment_image_pull_secrets["name"] = "test-yaml-container-secret";

    deployment["spec"]["template"]["spec"]["imagePullSecrets"].Insert(0);

    deployment["spec"]["template"]["spec"]["containers"].Insert(0);

    deployment["spec"]["template"]["spec"]["imagePullSecrets"][0] = deployment_image_pull_secrets;

    deployment["spec"]["template"]["spec"]["containers"][0] = deployment_containers;

    string result;
    Yaml::Serialize(deployment,result);

    cout << result << endl;

}


int main(){

    // Example_UseJsonString();

    Example_UseYamlString();

    return 0;
}