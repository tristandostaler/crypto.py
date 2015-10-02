#!/usr/bin/python
import string
import base64
import sys
import binascii
#from Crypto.Util.strxor import strxor
import Crypto.Util.strxor

def rot13(argv):
    argv.append(13)
    return rotX(argv)

def rotX(argv):
    s = argv[0]
    shift = int(argv[1])
    lower_alphabet = string.ascii_lowercase
    upper_alphabet = string.ascii_uppercase
    shifted_lower_alphabet = lower_alphabet[shift:] + lower_alphabet[:shift]
    shifted_upper_alphabet = upper_alphabet[shift:] + upper_alphabet[:shift]
    _rotX = string.maketrans(lower_alphabet + upper_alphabet, shifted_lower_alphabet + shifted_upper_alphabet)
    return string.translate(s, _rotX)

def b64e(argv):
    s = argv[0]
    return base64.b64encode(s)

def b64d(argv):
    s = argv[0]
    return base64.b64decode(s)

def caesar(argv):
    plaintext = argv[0].lower()
    shift = 3
    if len(argv) == 2:
        shift = int(argv[1])
    alphabet = string.ascii_lowercase
    shifted_alphabet = alphabet[shift:] + alphabet[:shift]
    table = string.maketrans(alphabet, shifted_alphabet)
    return plaintext.translate(table)

def textToSBits(argv):
    text = argv[0]
    encoding='utf-8'
    errors='surrogatepass'
    if len(argv) > 1:
        encoding = argv[1]
    if len(argv) > 2:
        errors = argv[2]
    bits = bin(int(binascii.hexlify(text.encode(encoding, errors)), 16))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))

def sBitsToText(argv):
    bits = argv[0].replace(" ", "").replace("\n", "").replace("\t", "")
    n = "";
    for i in range(0, len(bits), 8):
        if i + 8 < len(bits):
            n += chr(int(bits[i:i+8], 2))
        else:
            n += chr(int(bits[i:], 2))
    return n

def xor(argv):
    b1 = int(argv[0], 2)
    b2 = int(argv[1], 2)
    return bin(int(b1 ^ b2))[2:]

def xorFromHex(argv):
    s = binascii.unhexlify(argv[0])
    t = binascii.unhexlify(argv[1])
    u = strxor([s, t])
    return u

def strxor(argv):
    return Crypto.Util.strxor.strxor(argv[0], argv[1])

def strxor_c(argv):
    return Crypto.Util.strxor.strxor_c(argv[0], int(argv[1]))

def hexlify(argv):
    return binascii.hexlify(argv[0])

def hexlifyNoNewLine(argv):
    return binascii.hexlify(argv[0].replace("\n", ""))

def unhexlify(argv):
    return binascii.unhexlify(argv[0])

def unhexlifyNoNewLine(argv):
    return binascii.unhexlify(argv[0].replace("\n", ""))

def hexToBase64(argv):
    s = argv[0]
    decoded = binascii.unhexlify(s)
    return base64.b64encode(decoded).decode('ascii')

def base64ToHex(argv):
    s=argv[0]
    return hexlify([b64d([s])])

def hexToBits(argv):
    my_hexdata = argv[0]
    scale = 16 ## equals to hexadecimal
    #num_of_bits = 8
    num_of_bits = (len(my_hexdata) / 2) * 8
    return bin(int(my_hexdata, scale))[2:].zfill(num_of_bits)

def bitsToHex(argv):
    return str(hex(int(argv[0], 2))).replace("0x", "").replace("L", "")

def stringToHex(argv):
    return argv[0].encode("hex")

def hexToString(argv):
    return argv[0].decode("hex")

def findHigherValueInArrayIndex(argv):
    higher = argv[0]
    for i in range(len(argv)):
        if argv[i] > higher:
            higher = argv[i]
    return argv.index(higher)

def findHigherValueInArray(argv):
    higher = argv[0]
    for i in range(len(argv)):
        if argv[i] > higher:
            higher = argv[i]
    return higher

def bruteForceCaesarAndRotX(argv):
    res = [""]
    for i in range(0, 27):
        args = list(argv)
        args.append(i)
        res.append(caesar(args))
        res.append(rotX(args))
    #resValues = weightOrderedByLettersFrequency(res)
    resValues = getTotalWeightByLettersAndWord(res)
    return res[findHigherValueInArrayIndex(resValues)]

def bruteForceCaesarAndRotXAllResults(argv):
    res = [""]
    for i in range(0, 27):
        args = list(argv)
        args.append(i)
        res.append(caesar(args))
        res.append(rotX(args))
        print "Caesar " + str(i) + ": " + caesar(args)
        print "RotX " + str(i) + ": " + rotX(args)
    resValues = getTotalWeightByLettersAndWord(res)
    return resValues

def bruteForceSingleCharXORFromHex(argv):
    res = [""]
    for x in range(0, 256):
        res.append(strxor_c([unhexlify(argv), x]))
    #resValues = weightOrderedByLettersFrequency(res)
    resValues = getTotalWeightByLettersAndWord(res)
    return res[findHigherValueInArrayIndex(resValues)]

def bruteForceSingleCharXORFromHexAllResults(argv):
    res = [""]
    for x in range(0, 256):
        res.append(strxor_c([unhexlify(argv), x]))
    #resValues = weightOrderedByLettersFrequency(res)
    resValues = getTotalWeightByLettersAndWord(res)
    return res + resValues

def bruteForceMultipleCharXORFromHex(argv):
    res = [""]
    
    
    return res

def multipleCharXORFromStringAndKey(argv):
    #var = argv[0]
    #argv[0] = argv[1]
    #argv[1] = var
    if len(argv[0]) != len(argv[1]):
        if len(argv[0]) < len(argv[1]):
            argv[1] = argv[1][0:len(argv[0])]
        else:
            while len(argv[0]) > len(argv[1]):
                for i in range(len(argv[1])):
                    argv[1] += argv[1][i]
            if len(argv[0]) < len(argv[1]):
                argv[1] = argv[1][0:len(argv[0])]
    print argv[0]
    print argv[1]
    return multipleCharXORFromStringSameLengthKey(argv)

def multipleCharXORFromStringSameLengthKey(argv):
    var1 = stringToHex([argv[0]])
    var2 = stringToHex([argv[1]])
    return multipleCharXORFromHex([var1, var2]);

def multipleCharXORFromHex(argv):
    var1 = unhexlify([argv[0]])
    var2 = unhexlify([argv[1]])
    return hexlify([strxor([var1, var2])])

def getTotalWeightByLettersAndWord(argv):
    res = []
    for i in range(len(argv)):
        res.append(getWeightByLetterFrequencyForSingleValue([argv[i]]) + getWeightOrderedByWordsAppearanceForSingleValue([argv[i]]))
    return res

def weightOrderedByLettersFrequency(argv):
    #for i in range(len(argv)):
    #    argv[i].lower()

    res = []
    for i in range(len(argv)):
        res.append(getWeightByLetterFrequencyForSingleValue([argv[i]]))
        #for j in range(len(argv[i])):
        #    if orderedTable.__contains__(argv[i][j]):
        #        index = orderedTable.index(argv[i][j])
        #        res[i] += orderedValues[index]
    return res

def getWeightByLetterFrequencyForSingleValue(argv):
    try:
        argv[0].lower().decode('ascii')
    except:
        return 0
    orderedTable = ['e', 't', 'a', 'o', 'i', 'n', 's', 'r', 'h', 'd', 'l', 'u', 'c', 'm',
                    'f', 'y', 'w', 'g', 'p', 'b', 'v', 'k', 'x', 'q', 'j', 'z', ' ']
    orderedValues = [26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,
                     9, 8, 7, 6, 5, 4, 3, 2, 1, 27]
    total = 0;
    for j in range(len(argv[0])):
            if orderedTable.__contains__(argv[0][j]):
                index = orderedTable.index(argv[0][j])
                total += orderedValues[index]
    return total

def weightOrderedByWordsAppearance(argv):
    res = []
    for i in range(len(argv)):
        res.append(getWeightOrderedByWordsAppearanceForSingleValue([argv[i]]))
    return res

def getWeightOrderedByWordsAppearanceForSingleValue(argv):
    total = 0
    try:
        argv[0].lower().decode('ascii')
    except:
        return 0
    with open("./cryptoWordDictio.txt") as f:
        allWords = f.readlines()
        allWords = removeNonASCIIChars(allWords)
        for i in range(len(allWords)):
            word = allWords[i].replace("\n", "").lower()
            if argv[0].__contains__(word):
                total += len(allWords) - i
    return total

def callFunctionMultipleTimes(argv):
    res = []
    for i in range(0, int(argv[0])):
        try:
            res.append(globals()[argv[1]]([argv[2:]]))
        except:
            res.append("Error with: " + argv[2:] + ": " + str(sys.exc_info()[0]))
    return res

def callFunctionForEachLineInFileShowLine(argv):
    res = []
    with open(argv[0]) as f:
        content = f.readlines()
        for i in range(len(content)):
            try:
                res.append("Line " + str(i) + ": " + str(globals()[argv[1]]([content[i].replace("\n", "")])))
            except:
                res.append("Error with: " + content[i] + ": " + str(sys.exc_info()[0]))
    return res

def callFunctionForEachLineInFile(argv):
    res = []
    with open(argv[0]) as f:
        content = f.readlines()
        for i in range(len(content)):
            try:
                res.append(str(globals()[argv[1]]([content[i].replace("\n", "")])))
            except:
                res.append("Error with: " + content[i] + ": " + str(sys.exc_info()[0]))
    return res

def callFunctionForEachLineInFileDontAppendEmpty(argv):
    res = []
    with open(argv[0]) as f:
        content = f.readlines()
        for i in range(len(content)):
            try:
                r = str(globals()[argv[1]]([content[i].replace("\n", "")]))
                if r != "":
                    res.append("Line " + str(i) + ": " + r)
            except:
                res.append("Error with: " + content[i] + ": " + str(sys.exc_info()[0]))
    return res

def fileLinesToArray(argv):
    res = []
    with open(argv[0]) as f:
        content = f.readlines()
        for i in range(len(content)):
            res.append(content[i].replace("\n", ""))
    return res

def printValueFromArrayAtIndex(argv):
    return arrayAsStringToArray([argv[1]])[int(argv[0]) + 1]

def arrayAsStringToArray(argv):
    reta = argv[0].split(', ')
    for i in range(len(reta)):
        reta[i] = reta[i].replace("[", "").replace("]", "").replace("'", "")
    return reta

def removeNonASCIIChars(argv):
    for i in range(len(argv)):
        argv[i] = argv[i].decode("utf-8").encode("ascii", "replace").replace("?", "")
    return argv

if __name__ == '__main__':
    firstIndex = 1
    toLower = 0
    toUpper = 0
    removeSpace = 0
    removeNewLine = 0
    piped = 0
    outputToFile = 0
    inputIsArrayString = 0
    supportNewLineInReceivedString = 0
    if len(sys.argv) > 1:
        if "-" in sys.argv[1]:
            firstIndex = 2
            if "h" in sys.argv[1]:
                print globals().keys()
                exit()
            if "t" in sys.argv[1]:
                print "TEST OPTION"

                exit()
            if "l" in sys.argv[1]:
                toLower = 1
            if "u" in sys.argv[1]:
                toUpper = 1
            if "s" in sys.argv[1]:
                removeSpace = 1
            if "n" in sys.argv[1]:
                removeNewLine = 1
            if "p" in sys.argv[1]:
                piped = 1
            if "o" in sys.argv[1]:
                outputToFile = 1
            if "a" in sys.argv[1]:
                inputIsArrayString = 1
            if "m" in sys.argv[1]:
                supportNewLineInReceivedString = 1
    else:
        print globals().keys()
        exit()

    if piped == 0:
        attr = sys.argv[firstIndex + 1:]
    else:
        if len(sys.argv) > 3:
            attr = sys.argv[firstIndex + 1:] + sys.stdin.readlines()
        else:
            attr = sys.stdin.readlines()

    if inputIsArrayString == 1:
        attr = arrayAsStringToArray(attr)

    if supportNewLineInReceivedString == 1:
        for i in range(len(attr)):
            attr[i] = attr[i].replace("\\n", "\n")

    ret = str(globals()[sys.argv[firstIndex]](attr))

    #if piped == 0:
    #    ret = str(globals()[sys.argv[firstIndex]](sys.argv[firstIndex + 1:]))
    #else:
    #    if len(sys.argv) > 3:
    #        ret = str(globals()[sys.argv[firstIndex]](sys.argv[firstIndex + 1:] + sys.stdin.readlines()))
    #    else:
    #        ret = str(globals()[sys.argv[firstIndex]](sys.stdin.readlines()))

    if toLower == 1:
        ret = ret.lower()
    else:
        if toUpper == 1:
            ret = ret.upper()

    if removeSpace == 1:
        ret = ret.replace(' ', '')

    if removeNewLine == 1:
        ret = ret.replace('\n', '')

    if outputToFile == 1:
        with open("./resultCrypt.out", 'w') as f:
            reta = ret.split(', ')
            for i in range(len(reta)):
                reta[i] = reta[i].replace("[", "").replace("]", "").replace("'", "") + "\n"
                f.writelines(reta[i])
    else:
        print ret
