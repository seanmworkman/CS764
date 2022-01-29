import sys

def getBin(m):
    tmp = ''.join(format(ord(i), '08b') for i in m)
    binStr = tmp[0:int((len(tmp))/2)] + " " + tmp[int((len(tmp))/2):]
    return binStr

def g(h):
    result = ""
    for i in h:
        if i == "0":
            result += "1"
        elif i == "1":
            result += "0"
        else:
            result += i
    return result

def xor(a, b):
    result = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            result += "0"
        else:
            result += "1"

    return result

def hashFunc(strArray):
    h0 = "0101 1000"
    h = ""
    m = ""
    hashes = []
    result = ""

    for i in range(len(strArray)):
        if i == 0:
            h = h0
        else:
            h = hashes[i - 1]

        gh = g(h)

        m = getBin(strArray[i])

        lk = gh.split(" ")[0]
        rk = gh.split(" ")[1]

        lt = m.split(" ")[0]
        rt = m.split(" ")[1]

        lc = xor(lk, rt)
        rc = xor(rk, lt)
        hashes.append(lc + " " + rc)

    return ' '.join(hashes)

def binToString(binStr):
    result = ""
    splitBin = binStr.split(" ")
    for i in range(0, len(splitBin), 2):
        result += splitBin[i] + splitBin[i+1] + " "

    return result


hashResult = hashFunc(sys.argv[1])
print("Hash:", hashResult)

print("Hash:", binToString(hashResult))








