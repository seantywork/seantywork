# Rewriting Flatbuffer based CPP Sensor Data Server into Node JS 


[Context](#context)

[Oh my god, what did they do to you?](#oh-my-god-what-did-they-do-to-you)

[Challenges](#challenges)

[Muddling through](#muddling-through)

[JESUS CHRIST PLEASE DON'T](#jesus-christ-please-dont)

[Finger Kung Fu](#finger-kung-fu)

[Testing Out](#testing-out)

## Context

We all know from time to time, as a developer, one has to face the destiny where he is called upon a task that has been neglected,\
poorly documented, and at some point totally abondoned along the way of business of life.\
Ever since I started programming I've always heard this saying that the worst thing you could face as a developer is facing with the exactly that\
kind of codes. Be it Java, Javascript, Python, Go, you will always face the dreaded patterns and should do your best to avoid it when you're in charge.\
But the legend had it that if that kind of code is written in C++ or C, then that's the time for you to brace yourself for the\
nightmare that can forever change (for better or worse) the love you have for coding/programming.

That was exactly what happened to me a week away from Christmas, 2023.


## Oh my god, what did they do to you?

Well, the thing is, I cannot show you the codes and build system (or the absence of it) because I'm legally not permitted to do so.

But I think it's safe to write down some codes that implement the gist of the situation.\
Before laying down some of them, Here are key takeaways to keep in mind.

- It's written in C++ three years ago by a single guy with the total lines of code amounting to 15,000 and never retouched

- It uses Flatbuffer (yes, "FLAT"buffer. Not "PROTOCOL"buffer) for the serialization

- There are few comments and they are so arbitrary that it actually makes you feel elated when it is helpful in guiding you through the process

- I can deal with the fact that everything is in a single file, but why does SensorData2String reside in AIDATA.cpp while AIDATA2String is in SensorData.cpp?? 

- And why did you leave out all the essential information for building the project (flatc version, header include path, header files, link libraries and their versions...) and just tell me "make" (just simply "make", not cmake or wget or curl or apt or anything) would work, whereas it is absolutely insufficient to do anything.

It took me two whole days of infinite make-ing and apt-get-ing to get it just up and running!

I was briefly relieved that I finally got it to run at least, but that was the only the beginning of the real challenge.

I had to convert this mysterious and intractable C++ code base that uses Flatbuffer a lot into a maintainable and friendly NodeJS one.

*pseudocode will follow soon*

[pseudocode](thecode)


## Challenges


After all, as I finally got to the point where I could somehow get a grasp of what the heck is going on inside this enigma\
a few challenges I had to deal with emerged

1. Seeing the typed C++ code base and thinking of rewriting them in Javascript was already terrifying enough 

Plus, I had no idea how Typescript works nor the time to learn it

2. Javascript is one hell of an amazing language. But I had no previous experience in seeing how it speaks the concept in C++


Especially, within this context, reconciling async/await in Javascript and threads in C++ seemed like a devil as the C++ code used it a lot.\
And not only that, I had my own doubt that single-threaded Javascript event loop would be sufficient to handle what the C++ code handled previously.

3. Shame on me, but I rarely used Javascript Class when it's up to me

And even when I use C++, I'm not super fan of going with classes. But in the code, everything except for the main was class.\
And I also had no time to redesign the whole structure as my marginal understanding of the code base didn't let me to take the risk and\
redesign the whole thing in functional way because I had only two weeks for the whole 15,000 lines. What that meant was,\
if I make tweaks in the underlying logics and then later find out something is horrendously off, there will not be enough\
resource to recover. (though as I made progress it seemed more and more appropriate if everything in there was functional from the first place) 

Those were what frightened me.


## Muddling through

To do this properly, in a stark contrast to the usual myself, I made a list that looks somewhat similar to the below one on Notion

- Strategy
- Issue
- Disaster*
- Flow
- Messages
- Progress

*: *Disaster was later added due to an incident* 

**Strategy** contains the sort of principles that I thought I had to stick to, which include 


&nbsp;&nbsp;&nbsp;&nbsp; 1. Let's NEVER fiddle with the underlying logic until fully completing one cycle\
&nbsp;&nbsp;&nbsp;&nbsp; 2. Let's implement depth first, not breadth first\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; - This was because I got the impresson while scheming through the code that there is some fair amount of common building blocks\
&nbsp;&nbsp;&nbsp;&nbsp; 3. Among the packet receiver part, message handler part, and DB querying part, let's prioritize the first two\
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; - This was because the last part seemed fairly easier and repetitive compared to the first two parts\
&nbsp;&nbsp;&nbsp;&nbsp; ... and so on


**Issue** has all the things that \*IF\* anything unfathomable happens along the way as I debug and test the codes, I have to look for immediately.\
Namely, some unfathomable logic in calculating nd arrays and missing logics that seemed were supposed to be there for constructing session structure

**Flow** is where the overall control flow is laid out so that anyone who might follow me into this would easily get the whole structure, unlike me in the beginning

**Messages** is the single most important block of it all. Because this section has all the information of each packet including whether a packet of interest\
has been implemented, tested, has a client side example, and the location of the packet handler within the code base

**Progress** is where I documented daily status of progress, marked with the date

At first my intention in keeping this was to not get any unnecessary poking around from my superior about the progress, but soon it turned out\
to be one great way to organize my development path forward by checking out the actual amount of time taken to complete each component.

For example, when I first saw the below output of [cloc](https://github.com/AlDanial/cloc), I had no idea how I would break those down into\
actionable time chunks.


```shell

github.com/AlDanial/cloc v 1.82  T=0.79 s (2403.2 files/s, 474589.8 lines/s)
-------------------------------------------------------------------------------
Language                     files          blank        comment           code
-------------------------------------------------------------------------------
C/C++ Header                   138           7534           6827          61815
C++                             93           6255           4536          48610
```

However, as I gave up planning all the way and just started coding the functions one by one,\
I figured out that was unexpectedly efficient as I was able to collect the actual detailed data on how\
I had progressed, as shown below.


```shell
December 21, 2023 

- class DEVICE_LIST
- class LOG_QUEUE
- class REUSE_QUEUE
- class IP_BAN_LIST

December 22, 2023 

- global g_add_log
- global get_time_string
- global Init_Server
- global GetNewClientID
- global GetClientRange
- global packet_id_to_string
- global do_log_print
- global get_schedules
- global find_controller
- global process_schedule
- global do_ai
- global do_cleaning
- global disconnect_validated_devices
- global do_device_update
- class server
- class ssl_server
- Packet receiver completed

December 26, 2023 

- class player 
- session::send_XX completed
- working on message handler 

...


January 3, 2024 

- influxdb querying part completed
- class INFLUX_SENSOR_DATA

January 4, 2024 

- mysql querying part completed
- class MYSQL_SENSOR_DATA
- all db querying parts completed
- first draft completed, scheduled for endpoint test using available client sample data on tomorrow

January 5, 2024 

- endpoint test completed

```


Well, given how unoranized the C++ code was at first, I feel pretty proud of my self for converting everything in two weeks\
though, this could have taken even shorter if there were not "the incident"....


## JESUS CHRIST PLEASE DON'T

Calling out Jesus' name after more than a decade of not attending church was all because I had not carefully read the Flatbuffer message file\
and gone too fast without checking on some necessary details.

There are few things to note when serializing and deserializing Flatbuffer messages.

1. Your main target of serialization is Table type
   
```shell

# it usually looks like this
# you can see those familiar scalar types


table SOMETHING {
	Blah1 : int;
	Blah2 : short;
	Blah3 : short;	
}


```


2. And then you have Struct type

```shell

# looking like this


struct SOMETHING_STRUCT {
	Blah1 : int;
	Blah2 : short;
	Blah3 : short;	
}

# looks a lot like table type but this type usually
# goes under a table type as its field
# like below

table SOMETHING {
	Blah1 : int;
	Blah2 : short;
	Blah3 : short;
    Blah4 : SOMETHING_STRUCT;	
}


```

3. Finally (which turned out not to be), there is Array type

```shell

table SOMETHING {
	Blah1 : int;
	Blah2 : short;
	Blah3 : short;
    Blah4 : SOMETHING_STRUCT;	
    Blah5 : [byte];
    Blah6 : [SOMETHING_STRUCT];
}

```

Flatbuffer is a message type that goes even further beyond the hassel you first face when dealing with Protocolbuffer\
in exchange for better memory efficiency.

You have to finish creating a field of Array type before adding other scalar fields.

Hence, the building of the final byte buffer to be sent looks very weird and tedious.

C++ example, which doesn't look so pleasant, of it is:

```cpp

/*
message for below serialization looks like this


struct EXAMPLE_DATA {
    Val1 : short;
    Val2 : int;
}

table EXAMPLE_DATA_TABLE {
    FIELD1 : int;
    FIELD2 : short;
    FIELD3 : short;
    EXAMPLE_DATA : [EXAMPLE_DATA];	
}

*/

flatbuffers::FlatBufferBuilder fbb;


auto example_data1 = EXAMPLE_DATA(example_short, example_int);

auto example_data2 = EXAMPLE_DATA(example_short, example_int);

EXAMPLE_DATA eds[2] = { example_data1, example_data2 };

// this has to come before we initiate exdt_builder(fbb)

auto eds_offset = fbb.CreateVectorOfStructs(eds, 2);

EXAMPLE_DATA_TABLEBuilder exdt_builder(fbb);

exdt_builder.add_FIELD1(field1_val);

exdt_builder.add_FIELD2(field2_val);

exdt_builder.add_FIELD3(field3_val);

exdt_builder.add_EXAMPLE_DATA(eds_offset);

auto message = exdt_builder.Finish();

fbb.Finish(message);

```

Javascript equivalent, which looks fantasitic(ally bad for your finger joints and eyes), is:


```js

let builder = new flatbuffers.Builder()


fbproto.EXAMPLE_DATA_TABLE.startExampleDataVector(builder, 2)

for(let i = 0; i < 2; i++){


    fbproto.EXAMPLE_DATA.createEXAMPLE_DATA(
        builder,
        example_short, 
        example_int
    )


}

// if below line goes anywhere after startEXAMPLE_DATA_TABLE, it will throw error

let eds_offset = builder.endVector()

fbproto.EXAMPLE_DATA_TABLE.startEXAMPLE_DATA_TABLE(builder)

fbproto.EXAMPLE_DATA_TABLE.addField1(builder, field1_val)

fbproto.EXAMPLE_DATA_TABLE.addField2(builder, field2_val)

fbproto.EXAMPLE_DATA_TABLE.addField3(builder, field3_val)

fbproto.EXAMPLE_DATA_TABLE.addExampleData(builder, eds_offset)

let root_table = fbproto.EXAMPLE_DATA_TABLE.endEXAMPLE_DATA_TABLE(builder)

builder.finish(root_table)
    


```


It was already too bloated to process for me at the moment, but I had fought it and fought it hard....\
until I found out that there is a particular way to handle "string" type and was unable to serialize it properly.

In Protocolbuffer, adding it to a field is just as simple as other types ex) int, short...

However, at that very moment when I was puzzled by the null string field even though\
I triple checked that I had added "test" to the field, I realized I had failed to appereciate \
the full extent of this Flatbuffer's amazing feat that refuses to take the road already taken by Protocolbuffer.


```js

/*

if our beloved EXAMPLE_DATA_TABLE has a string array field like below one


table EXAMPLE_DATA_TABLE {
    FIELD1 : int;
    FIELD2 : short;
    FIELD3 : short;
    EXAMPLE_DATA : [EXAMPLE_DATA];	
    STR_FIELD : [string];
}

then javascript code will become like this....

*/


let builder = new flatbuffers.Builder()

// adding this tmp array
let tmp = []

fbproto.EXAMPLE_DATA_TABLE.startExampleDataVector(builder, 2)

for(let i = 0; i < 2; i++){




    fbproto.EXAMPLE_DATA.createEXAMPLE_DATA(
        builder,
        example_short, 
        example_int
    )

    tmp.push(example_str)

}


let eds_offset = builder.endVector()


// yes, another loop just to serialize these strings

for (let i = 0 ; i < 2; i ++){

    tmp[i] = builder.createString(tmp[i])
}

// below line cannot go anywhere after startEXAMPLE_DATA_TABLE 
// or
// before builder.endVector() 
//
// happy coding!!!! :) 

let str_field_offset = fbproto.EXAMPLE_DATA_TABLE.createStrFieldVector(builder, tmp)

fbproto.EXAMPLE_DATA_TABLE.startEXAMPLE_DATA_TABLE(builder)

fbproto.EXAMPLE_DATA_TABLE.addField1(builder, field1_val)

fbproto.EXAMPLE_DATA_TABLE.addField2(builder, field2_val)

fbproto.EXAMPLE_DATA_TABLE.addField3(builder, field3_val)

fbproto.EXAMPLE_DATA_TABLE.addExampleData(builder, eds_offset)

fbproto.EXAMPLE_DATA_TABLE.addStrField(builder, str_field_offset)

let root_table = fbproto.EXAMPLE_DATA_TABLE.endEXAMPLE_DATA_TABLE(builder)

builder.finish(root_table)
    


```



And the problem was, among 42 messages, with its evil implication, string type was lurking in almost every table type I had already\
(thought to have) completed.

There I cried Jesus Christ with the sincerity I had never been able to garner when I read bible at the behest of my father.



## Finger Kung Fu






```shell
github.com/AlDanial/cloc v 1.82  T=0.79 s (2403.2 files/s, 474589.8 lines/s)
-------------------------------------------------------------------------------
Language                     files          blank        comment           code
-------------------------------------------------------------------------------
C/C++ Header                   138           7534           6827          61815
C++                             93           6255           4536          48610
JavaScript                     320           6684           4228          38781

```


## Testing out