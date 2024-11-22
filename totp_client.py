import pyotp
import sys
import time

def import_key(username: str):
    try:
        with open("otp_keys/"+username+'.txt', 'r') as file:
            key = file.read().strip()
        return key
    except FileNotFoundError:
        print("Key not found")
        sys.exit(1)

def main(argv):
    if len(argv) != 2:
        print("Usage: python totp_client.py <username>")
        sys.exit(1)
    username = argv[1]

    key = import_key(username)

    totp = pyotp.TOTP(key)

    code = totp.now()
    print(f"Code: {code}")

    while True:
        time_left = 30 - time.time() % 30
        if time_left <= 0.01:
            print("Time's up!                                     ")
            break
        print(f"Time remaining: " + str(round(time_left, 1)), end='\r')


if __name__ == '__main__':
    try:
        main(sys.argv)
    except KeyboardInterrupt:
        exit(1)
