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

	// this right here is a Go specific way of something equivalent to appending an element at the end of an array (slice)

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

	// if not make() it, you will see an error that you're trying to assign to a nil map

	var test_deployment = make(map[string]interface{})

	var test_image_pull_secrets = make(map[string]interface{})

	var test_containers = make(map[string]interface{})

	var test_containers_ports = make(map[string]interface{})

	_ = json.Unmarshal([]byte(Deployment_json_string), &test_deployment)

	_ = json.Unmarshal([]byte(Deployment_ImagePullSecrets_json_string), &test_image_pull_secrets)

	_ = json.Unmarshal([]byte(Deployment_Containers_json_string), &test_containers)

	_ = json.Unmarshal([]byte(Deployment_Containers_Ports_json_string), &test_containers_ports)

	test_containers_ports["containerPort"] = 3306

	test_containers["name"] = "test-json-container"
	test_containers["image"] = "docker.io/test/json-container"
	test_containers["imagePullPolicy"] = "Always"

	test_containers["ports"] = append(test_containers["ports"].([]interface{}), test_containers_ports)

	test_image_pull_secrets["name"] = "test-json-container-secret"

	test_deployment["apiVersion"] = "apps/v1"
	test_deployment["kind"] = "Deployment"
	test_deployment["metadata"].(map[string]interface{})["name"] = "test-json"

	// read carefully the code right below
	// though not explicitly being a pointer or a reference type,
	// the variable on the left side is a reference to the right one

	test_deployment_spec := test_deployment["spec"].(map[string]interface{})

	test_deployment_spec["selector"].(map[string]interface{})["matchLabels"].(map[string]interface{})["app"] = "test-json"

	test_deployment_spec["replicas"] = 1

	test_deployment_spec_template := test_deployment_spec["template"].(map[string]interface{})

	test_deployment_spec_template["metadata"].(map[string]interface{})["labels"].(map[string]interface{})["app"] = "test-json"

	test_deployment_spec_template["spec"].(map[string]interface{})["imagePullSecrets"] = append([]interface{}{}, test_image_pull_secrets)

	test_deployment_spec_template["spec"].(map[string]interface{})["containers"] = append([]interface{}{}, test_containers)

	json_string_b, err := json.Marshal(test_deployment)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	err = os.WriteFile("test_string.json", json_string_b, 0644)

	if err != nil {
		fmt.Println(err.Error())
	}

}

func Example_USeYamlString() {

	var test_deployment = make(map[interface{}]interface{})

	var test_image_pull_secrets = make(map[interface{}]interface{})

	var test_containers = make(map[interface{}]interface{})

	var test_containers_ports = make(map[interface{}]interface{})

	_ = yaml.Unmarshal([]byte(Deployment_yaml_string), &test_deployment)

	_ = yaml.Unmarshal([]byte(Deployment_ImagePullSecrets_yaml_string), &test_image_pull_secrets)

	_ = yaml.Unmarshal([]byte(Deployment_Containers_yaml_string), &test_containers)

	_ = yaml.Unmarshal([]byte(Deployment_Containers_Ports_yaml_string), &test_containers_ports)

	test_containers_ports["containerPort"] = 3306

	test_containers["name"] = "test-yaml-container"
	test_containers["image"] = "docker.io/test/yaml-container"
	test_containers["imagePullPolicy"] = "Always"

	test_containers["ports"] = append(test_containers["ports"].([]interface{}), test_containers_ports)

	test_image_pull_secrets["name"] = "test-yaml-container-secret"

	test_deployment["apiVersion"] = "apps/v1"
	test_deployment["kind"] = "Deployment"
	test_deployment["metadata"].(map[string]interface{})["name"] = "test-yaml"

	test_deployment_spec := test_deployment["spec"].(map[string]interface{})

	test_deployment_spec["selector"].(map[string]interface{})["matchLabels"].(map[string]interface{})["app"] = "test-yaml"

	test_deployment_spec["replicas"] = 1

	test_deployment_spec_template := test_deployment_spec["template"].(map[string]interface{})

	test_deployment_spec_template["metadata"].(map[string]interface{})["labels"].(map[string]interface{})["app"] = "test-yaml"

	test_deployment_spec_template["spec"].(map[string]interface{})["imagePullSecrets"] = append([]interface{}{}, test_image_pull_secrets)

	test_deployment_spec_template["spec"].(map[string]interface{})["containers"] = append([]interface{}{}, test_containers)

	yaml_string_b, err := yaml.Marshal(test_deployment)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	err = os.WriteFile("test_string.yaml", yaml_string_b, 0644)

	if err != nil {
		fmt.Println(err.Error())
	}

}

func main() {

	Example_UseJsonStruct()

	Example_UseYamlStruct()

	Example_UseJsonString()

	Example_USeYamlString()

}
