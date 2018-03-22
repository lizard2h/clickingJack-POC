import optparse
import requests
import sys
import webbrowser

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
    Newurl = "http://" + url
    iframe = """
    <html>
        <head><title>Clickjack test page</title></head>
        <body>
            <p>Website is vulnerable to clickjacking!</p>
            <iframe src="{}" width="500" height="500"></iframe>
        </body>
    </html>
     """.format(Newurl)
    print("[+] Writing PoC !")
    writePoC(iframe)

def writePoC(iframe):

    try:
        f = open("/tmp/iframe.html", 'w')
        f.write(iframe)
        f.close()
        print("[+] File write with sucess.. you can now use in your browser")
    except Exception as e:
        print("[+] Something went wrong while writing file")
        print(e)

    ans = input("Do u want to open PoC in your browser y/n ? ".lower())
    if ans == "y":
        try:
            url = "file:///tmp/iframe.html"
            webbrowser.open(url)
        except Exception as e:
            print("[-] Error try install webbrowser lib !")
            print(e)  
    else:
         print("[+] Go to your Desktop and get the iframe.html!")

    

main()
