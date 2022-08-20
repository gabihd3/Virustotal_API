import re
import requests

f = open("/Example/Path/file.txt")
test = []
for i in f.readlines():
    fa = re.findall("[A-Fa-f0-9]{64}", i)
    test.append(fa)

empty = [i[0] for i in test]
empty = list(set(empty))

if len(empty) == 0:
    print("No hashes found in the file")

#Add VT check
