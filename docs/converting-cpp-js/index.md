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

and even when I use C++, I'm not super fan of going with classes. But in the code, everything except for the main was class.\
And I also had no time to redesign the whole structure as my marginal understanding of the code base didn't let me to take the risk and\
redesign the whole thing in functional way because I had only two weeks for the whole 15,000 lines. What that meant was,\
if I make tweaks in the underlying logics and then later find out something is horrendously off, there will not be enough\
resource to recover. (though as I made progress it seemed more and more appropriate if everything in there was functional from the first place) 

Those were what frightened me.


## Progress

To do this properly, in a stark contrast to the usual myself, I made a list that looks somewhat similar to the below one on Notion

- Strategy
- Issue
- Disaster*
- Flow
- Messages
- Progress

*: *Disaster was later added due to an incident* 

**Strategy** contains the sort of principles that I thought I had to stick to, which include
