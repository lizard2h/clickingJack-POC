import optparse
import requests
import sys

def main():
    parser = optparse.OptionParser(usage="python3 %prog -u <url> -c <cookies>")
    parser.add_option("-u", dest="url", default=False, help="url target", type="string")
    parser.add_option("-c", dest="cookies", default=False, help="cookies if auth page", type="string")
    (options, args) = parser.parse_args()
    urlTarget = options.url
    cookiesTarget = options.cookies

    if sys.argv[0] == None:
        print(parser.usage)


    if urlTarget == None or cookiesTarget == None:
        print(parser.usage)
        exit(0)
    else:
        check = checkUrl(urlTarget)
        if check:
            print("[+] Vulnerable making PoC")
            clickJPoc(urlTarget, cookiesTarget)
        else:
            print("[-] NOT Vulnerable")
            exit(0)

def checkUrl(url):
    if "http" not in url:
        Newurl = "http://" + url
    
    print("[+] Making request to {}".format(Newurl))
    try:
        r = requests.get(Newurl, allow_redirects=True)
        if not "X-Frame-Options" in r.headers:
            return True
        elif r.headers["X-Frame-Options"] == 'DENY':
            return True
        else:
            return False

    except Exception as e:
        print("[-] Error {}".format(e))


def clickJPoc(url, cookies=""):

    iframe = """
    <html>
        <head><title>Clickjack test page</title></head>
        <body>
            <p>Website is vulnerable to clickjacking!</p>
            <iframe src="{}" width="500" height="500"></iframe>
        </body>
    </html>
     """.format(url)
    print(iframe)




main()