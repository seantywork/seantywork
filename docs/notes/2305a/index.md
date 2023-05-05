## some pitfalls when doing networking stuff within kubernetes cluster

Setting up a Kubernetes cluster itself requires some unpleasant hassling all the way down to

tweaking dhcp and static IP address settings on your router, but even if you're done with it and see the whole 

cursed installation process through, there is still something left to handle if your intention is actually using the cluster,

not hoisting it idly.

And that is the networking part within the cluster. Usually, letting the applications (to be specific, pods) communicate with each other

is achieved by simply deploying a network resource of your choice, such as Weavenet, Calico, Flannel, to name a few.

But even after that, rooted in the core design and implementation of Kubernetes, there are a few pitfalls that will hold you back from

having a "fully functional" Kubernetes cluster if you fail to address them.

1. Service doesn't mean that the application (or pod) is open to the traffic outside the cluster

To actually serve the app, you need to properly deploy one of the next things.

 - Nodeport
 - Loadbalancer
 - Ingress

My go-tos are Nodeport and Ingress. 

2. Double-check if your "container" is ready to respond inside a pod

In the Kubernetes cluster, "Running" status doesn't always mean that your desired application is truly ready to serve the traffic


3. Client metadata should be handled carefully

It might be a Ingress-specific problem, or even specific to nginx ingress controller and nginx container pair, but failing to 

properly setting up Configmap for ingress controller can cause some serious headaches especially when you're trying to retrieve actual

user information, namely his or her IP address.



