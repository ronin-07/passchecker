import requests  # api access
import hashlib  # to convert text to sha1 hash


# return a response from api by taking first 5 hash digits 200 means api is working
def request_data(query):
    url = 'https://api.pwnedpasswords.com/range/' + query
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Check api and try again, error code: {res.status_code}')
    return res


# reads the response from api line by line and splits remaining hash digits and count
# checks if tail of hash matches or not and returns count
def get_count(hashes, to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == to_check:
            return count
    return 0


# first function to be called taking password in text and converting to sha1 hash
# calls count function which returns count
def api_check(password):
    sha1pass = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1pass[:5], sha1pass[5:]
    response = request_data(first5_char)
    return get_count(response, tail)


# driver function to read passwords from passwords.txt file
# and check if password has been leaked or not
if __name__ == '__main__':
    with open('passwords.txt', 'r') as file:
        lines = [line.rstrip('\n') for line in file]
        for pas in lines:
            count = api_check(pas)
            if count:
                print(f'{pas} was found {count} times... change your password to be safe')
            else:
                print(f'{pas} was NOT found! Dont forget to change it once in 2 months :) ')
