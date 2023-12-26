# Rewriting Flatbuffer based CPP Sensor Data Server into Node JS 


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

- And why did you leave out all the essential information for building the project (flatc version, header include path, header files, link libraries and their versions...) and just tell me "make" (just simply "make", not cmake or wget or curl or apt or anything) would work, whereas it is absolutely insufficient to do anything

It took me two whole days to get it just up and running!

I was briefly relieved that I finally got it to run at least, but that was the only the beginning of the real challenge.

I had to convert this mysterious and intractable C++ code base that uses Flatbuffer a lot into a maintainable and friendly NodeJS one.



## Challenges





## Progress