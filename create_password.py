import random
import string
def passwordGen():
    password = "".join([random.choice(string.ascii_letters + string.punctuation + string.digits) for n in range(12)])   
    print(len(password))
    print(password)

passwordGen()