exports.talkback = async function (event, context) {
    console.log("EVENT: \n" + JSON.stringify(event, null, 2));

    var talkback = {

       "name" : 'what do you need my name for?',

       "comment": 'get the hell off'

    }

    var ret_json = {
        "context_logstream_name" : context.logStreamName,
        "talkback": talkback
    }

    return ret_json
  };