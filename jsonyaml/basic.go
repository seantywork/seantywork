package main

import (
	"encoding/json"

	"fmt"
	"os"

	yaml "gopkg.in/yaml.v3"
)

func Example_UseJsonStruct() {

	var test_deployment Deployment

	var test_image_pull_secrets Deployment_ImagePullSecrets

	var test_containers Deployment_Containers

	var test_containers_ports Deployment_Containers_Ports

	test_containers_ports.ContainerPort = 1337

	test_containers.Name = "test-json-container"
	test_containers.Image = "docker.io/test/json-container"
	test_containers.ImagePullPolicy = "Always"
	test_containers.Ports = append(test_containers.Ports, test_containers_ports)

	test_image_pull_secrets.Name = "test-json-container-secret"

	test_deployment.APIVersion = "apps/v1"
	test_deployment.Kind = "Deployment"
	test_deployment.Metadata.Name = "test-json"
	test_deployment.Spec.Selector.MatchLabels.App = "test-json"
	test_deployment.Spec.Replicas = 1
	test_deployment.Spec.Template.Metadata.Labels.App = "test-json"
	test_deployment.Spec.Template.Spec.ImagePullSecrets = append(test_deployment.Spec.Template.Spec.ImagePullSecrets, test_image_pull_secrets)
	test_deployment.Spec.Template.Spec.Containers = append(test_deployment.Spec.Template.Spec.Containers, test_containers)

	json_struct_b, err := json.Marshal(test_deployment)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	err = os.WriteFile("test_struct.json", json_struct_b, 0644)

	if err != nil {
		fmt.Println(err.Error())
	}

}

func Example_UseYamlStruct() {

	var test_deployment Deployment

	var test_image_pull_secrets Deployment_ImagePullSecrets

	var test_containers Deployment_Containers

	var test_containers_ports Deployment_Containers_Ports

	test_containers_ports.ContainerPort = 1337

	test_containers.Name = "test-yaml-container"
	test_containers.Image = "docker.io/test/yaml-container"
	test_containers.ImagePullPolicy = "Always"
	test_containers.Ports = append(test_containers.Ports, test_containers_ports)

	test_image_pull_secrets.Name = "test-yaml-container-secret"

	test_deployment.APIVersion = "apps/v1"
	test_deployment.Kind = "Deployment"
	test_deployment.Metadata.Name = "test-yaml"
	test_deployment.Spec.Selector.MatchLabels.App = "test-yaml"
	test_deployment.Spec.Replicas = 1
	test_deployment.Spec.Template.Metadata.Labels.App = "test-yaml"
	test_deployment.Spec.Template.Spec.ImagePullSecrets = append(test_deployment.Spec.Template.Spec.ImagePullSecrets, test_image_pull_secrets)
	test_deployment.Spec.Template.Spec.Containers = append(test_deployment.Spec.Template.Spec.Containers, test_containers)

	yaml_struct_b, err := yaml.Marshal(test_deployment)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	err = os.WriteFile("test_struct.yaml", yaml_struct_b, 0644)

	if err != nil {
		fmt.Println(err.Error())
	}

}

func Example_UseJsonString() {

	var test_deployment = make(map[string]interface{})

	var test_image_pull_secrets = make(map[string]interface{})

	var test_containers = make(map[string]interface{})

	var test_containers_ports = make(map[string]interface{})

	_ = json.Unmarshal([]byte(Deployment_string), &test_deployment)

	_ = json.Unmarshal([]byte(Deployment_ImagePullSecrets_string), &test_image_pull_secrets)

	_ = json.Unmarshal([]byte(Deployment_Containers_string), &test_containers)

	_ = json.Unmarshal([]byte(Deployment_Containers_Ports_string), &test_containers_ports)

	test_containers_ports["containerPort"] = 3306

	test_containers["name"] = "test-json-container"
	test_containers["image"] = "docker.io/test/json-container"
	test_containers["imagePullPolicy"] = "Always"

	test_containers["ports"] = append([]interface{}{}, test_containers_ports)

	fmt.Println(test_containers)

}

func Example_USeYamlString() {

	// var test_deployment map[interface{}]interface{}

}

func main() {

	// Example_UseJsonStruct()

	// Example_UseYamlStruct()

	Example_UseJsonString()

}
