package main

type Deployment struct {
	APIVersion string `json:"apiVersion" yaml:"apiVersion"`
	Kind       string `json:"kind" yaml:"kind"`
	Metadata   struct {
		Name string `json:"name" yaml:"name"`
	} `json:"metadata" yaml:"metadata"`
	Spec struct {
		Selector struct {
			MatchLabels struct {
				App string `json:"app" yaml:"app"`
			} `json:"matchLabels" yaml:"matchLabels"`
		} `json:"selector" yaml:"selector"`
		Replicas int `json:"replicas" yaml:"replicas"`
		Template struct {
			Metadata struct {
				Labels struct {
					App string `json:"app" yaml:"app"`
				} `json:"labels" yaml:"labels"`
			} `json:"metadata" yaml:"metadata"`
			Spec struct {
				ImagePullSecrets []Deployment_ImagePullSecrets `json:"imagePullSecrets" yaml:"imagePullSecrets"`
				Containers       []Deployment_Containers       `json:"containers" yaml:"containers"`
			} `json:"spec" yaml:"spec"`
		} `json:"template" yaml:"template"`
	} `json:"spec" yaml:"spec"`
}

type Deployment_ImagePullSecrets struct {
	Name string `json:"name" yaml:"name"`
}

type Deployment_Containers struct {
	Name            string                        `json:"name" yaml:"name"`
	Image           string                        `json:"image" yaml:"image"`
	ImagePullPolicy string                        `json:"imagePullPolicy" yaml:"imagePullPolicy"`
	Ports           []Deployment_Containers_Ports `json:"ports" yaml:"ports"`
}

type Deployment_Containers_Ports struct {
	ContainerPort int `json:"containerPort" yaml:"containerPort"`
}

var Deployment_json_string = `
{
  "apiVersion": "apps/v1",
  "kind": "Deployment",
  "metadata": {
    "name": "string"
  },
  "spec": {
    "selector": {
      "matchLabels": {
        "app": "string"
      }
    },
    "replicas": "integer",
    "template": {
      "metadata": {
        "labels": {
          "app": "string"
        }
      },
      "spec": {
        "imagePullSecrets": [],
        "containers": []
      }
    }
  }
}
`

var Deployment_ImagePullSecrets_json_string = `
{
  "name": "string"
}
`

var Deployment_Containers_json_string = `
{
  "name": "string",
  "image": "string",
  "imagePullPolicy": "string",
  "ports": []
}
`

var Deployment_Containers_Ports_json_string = `
{
  "containerPort": "integer"
}
`

var Deployment_yaml_string = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: string
spec:
  selector:
    matchLabels:
      app: string
  replicas: integer
  template:
    metadata:
      labels:
        app: string
    spec:
      imagePullSecrets: []
      containers: []

`

var Deployment_ImagePullSecrets_yaml_string = `
name: string
`

var Deployment_Containers_yaml_string = `
name: string
image: string
imagePullPolicy: string
ports: []
`

var Deployment_Containers_Ports_yaml_string = `
containerPort: integer
`
