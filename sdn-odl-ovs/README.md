
# installed openjdk-21, maven

```shell
$ source ~/.profile
$ mvn -v 
Apache Maven 3.9.12 (848fbb4bf2d427b72bdb2471c22fced7ebd9a7a1)
Maven home: /home/seantywork/controller/apache-maven-3.9.12
Java version: 21.0.9, vendor: Ubuntu, runtime: /usr/lib/jvm/java-21-openjdk-amd64
Default locale: en, platform encoding: UTF-8
OS name: "linux", version: "6.14.0-1021-gcp", arch: "amd64", family: "unix"

```

# run bin/karaf

```shell
$ cd karaf-0.22.1
$ ./bin/karaf
seantywork@instance-20260102-074011:~/controller/karaf-0.22.1$ ./bin/karaf
karaf: JAVA_HOME not set; results may vary
Apache Karaf starting up. Press Enter to open the shell now...
100% [========================================================================]
Karaf started in 4s. Bundle stats: 69 active, 70 total
                                                                                           
    ________                       ________                .__  .__       .__     __       
    \_____  \ ______   ____   ____ \______ \ _____  ___.__.|  | |__| ____ |  |___/  |_     
     /   |   \\____ \_/ __ \ /    \ |    |  \\__  \<   |  ||  | |  |/ ___\|  |  \   __\    
    /    |    \  |_> >  ___/|   |  \|    `   \/ __ \\___  ||  |_|  / /_/  >   Y  \  |      
    \_______  /   __/ \___  >___|  /_______  (____  / ____||____/__\___  /|___|  /__|      
            \/|__|        \/     \/        \/     \/\/            /_____/      \/          
                                                                                           

Hit '<tab>' for a list of available commands
and '[cmd] --help' for help on a specific command.
Hit '<ctrl-d>' or type 'system:shutdown' or 'logout' to shutdown OpenDaylight.

opendaylight-user@root> 

```

# install controller features

```shell
# in karaf
feature:install odl-openflowjava-protocol \
odl-openflowplugin-nsf-model \
odl-openflowplugin-southbound \
odl-openflowplugin-app-config-pusher \
odl-openflowplugin-app-forwardingrules-manager \
odl-openflowplugin-app-forwardingrules-sync \
odl-openflowplugin-app-table-miss-enforcer \
odl-openflowplugin-app-topology \
odl-openflowplugin-nxm-extensions \
odl-openflowplugin-onf-extensions \
odl-openflowplugin-flow-services-rest

# then
logout

# then, again
$ ./bin/karaf

# on another terminal 
$ lsof -i -P -n
seantywork@instance-20260102-074011:~$ lsof -i -P -n
COMMAND  PID       USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
java    5968 seantywork   88u  IPv6  20533      0t0  TCP *:8101 (LISTEN)
java    5968 seantywork   94u  IPv6  20535      0t0  TCP *:8181 (LISTEN)
java    5968 seantywork   99u  IPv6  20150      0t0  TCP 127.0.0.1:1099 (LISTEN)
java    5968 seantywork  101u  IPv6  20151      0t0  TCP 127.0.0.1:44444 (LISTEN)
java    5968 seantywork  137u  IPv6  20144      0t0  TCP 127.0.0.1:35969 (LISTEN)
java    5968 seantywork  166u  IPv6  20540      0t0  TCP 127.0.0.1:2550 (LISTEN)
java    5968 seantywork  205u  IPv6  20233      0t0  TCP *:8182 (LISTEN)
java    5968 seantywork  230u  IPv6  20608      0t0  TCP *:6653 (LISTEN)
java    5968 seantywork  255u  IPv6  20609      0t0  TCP *:6633 (LISTEN)
```
