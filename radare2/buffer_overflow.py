
def DeadbeefOverflowPayload(bytes_len, endian):

    char_code = 64

    stuff_payload =  ""

    for i in range(bytes_len):

        if i % 10 == 0 :

            char_code += 1

        if char_code == 91 :

            char_code = 65

        stuff_payload += chr(char_code)

        

    if endian == "big":
        byte_payload = b"\xde\xad\xbe\xef"

    elif endian == "little":
        byte_payload = b"\xef\xbe\xad\xde"


    payload = "\""+stuff_payload+"\"" + " + "


    byte_output = str(byte_payload).replace('b','',1)

    byte_output = byte_output.replace('\'','')

    payload += "\""+byte_output+"\""


    return payload



if __name__ == "__main__":

    from config import *

    import sys

    if sys.argv[1] == "deadbeef-overflow":

        result = DeadbeefOverflowPayload(BUFFER_OVERFLOW_BYTES_LEN, BUFFER_OVERFLOW_ENDIAN)

        print(result)