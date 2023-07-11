package main

type Deployment struct {
	APIVersion string `json,yaml:"apiVersion"`
	Kind       string `json,yaml:"kind"`
	Metadata   struct {
		Name string `json,yaml:"name"`
	} `json,yaml:"metadata"`
	Spec struct {
		Selector struct {
			MatchLabels struct {
				App string `json,yaml:"app"`
			} `json,yaml:"matchLabels"`
		} `json,yaml:"selector"`
		Replicas int `json,yaml:"replicas"`
		Template struct {
			Metadata struct {
				Labels struct {
					App string `json,yaml:"app"`
				} `json,yaml:"labels"`
			} `json,yaml:"metadata"`
			Spec struct {
				ImagePullSecrets []Deployment_ImagePullSecrets `json,yaml:"imagePullSecrets"`
				Containers       []Deployment_Containers       `json,yaml:"containers"`
			} `json,yaml:"spec"`
		} `json,yaml:"template"`
	} `json,yaml:"spec"`
}

type Deployment_ImagePullSecrets struct {
	Name string `json,yaml:"name"`
}

type Deployment_Containers struct {
	Name            string                        `json,yaml:"name"`
	Image           string                        `json,yaml:"image"`
	ImagePullPolicy string                        `json,yaml:"imagePullPolicy"`
	Ports           []Deployment_Containers_Ports `json,yaml:"ports"`
}

type Deployment_Containers_Ports struct {
	ContainerPort int `json,yaml:"containerPort"`
}

var Deployment_string = `
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

var Deployment_ImagePullSecrets_string = `
name: string
`

var Deployment_Containers_string = `
name: string
image: string
imagePullPolicy: string
ports: []
`

var Deployment_Containers_Ports_string = `
containerPort: integer
`
