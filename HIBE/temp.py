import os

content = "dachsuiiov"
path = "./file/"
if not os.path.exists(path):
    os.makedirs(path)
fileName = path + "Msk.txt"
with open(fileName, "w") as f:
    f.write(str(content))