# 2304a: "fetch more projects", how to get web socket connection from another thread, the tough job they have at the fed

- "fetch more projects"

I'm working at a company where it's crucial to keep the flow of R&D projects running to pay out checks and bills.

In other words, this company is currently unable to generate some meaningful flow of cash without cooperating with some bigger institutions or

going after some low-correlated R&D projects.

Due to that circumstance, even developers, including myself of course, from time to time have to come up with some literary creativity and 

administrative rigor at the same time to earn his or her fair share at the company.

This certainly sounds damn discouraging for the developers who want to absolutely direct their resources to become another Gennady Korotkevich,

but from my perspective, there is a silver lining in doing this.

This teaches you how to survive in this industry (or even in this world in general) even when you strive to become the 10x developer and

fail to make it.

Got two new projects approved running 4 years and 2 years each.

- how to get web socket connection from another thread

Check out my repository [go-chat-frankenstein](https://github.com/seantywork/0014_go-chat-frankenstein) - /sio folder.

Basically, you make a map[string]*websocket.Conn and let whatever your authentication logic do the checking and if all is fine,

insert the key and the corresponding websocket connection pointer into the map.

Then, from another thread or even another program, you can retrieve the exact connection that you want to send to/receive from.

- the tough job they have at the fed

Jerome Powell and his colleagues at the Fed recently apologized for their lack of appropriate action against the troubled banks, which includes

SVB and Signature, when they first found out that the banks carried some serious risks of bank-running in the face of rate rise and 

following so and so. 

They got ranted by those who want them to stop raising the rate because they are smothering the American economy and job market

while also bashed by those who want them to do more to curb the crazy inflation because it is dismantling financial stability and 

the crucial trust in the Fed's role as the inflation fighter.

And now the fall of the banks is partly their failure...

Let's hope God help them get through this.
