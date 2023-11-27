# CTF 6 - SQL Injection

## 1. Reconnaissance

We were given a PHP file, named *index.php*, with code that ran on the server side every time a user attempted authenticate himself in the webpage. 
We were also told that the flag would be in a *flag.txt* file displayed to every authenticated user and that the challenge would be available at http://ctf-fsi.fe.up.pt:5003/.

![challenge](images/sql-injection-ctf/challenge.png)

We decided to attempt to login as a random user in order to check if the webpage would tell us anything about a specific user existing (or not).

![better-call-saul](images/sql-injection-ctf/better_call_saul.png)

However, the webpage told us nothing about there being a user named ```saul_goodman```.

## 2. Searching for/Choosing a Vulnerability

Before doing anything else, we decided to take a look at the *index.php* file, where we found the piece of PHP code that was ran every time a user attempted to authenticate.

```php
<?php
    if (!empty($_POST)) {

        require_once 'config.php';

        $username = $_POST['username'];
        $password = $_POST['password'];
               
        $query = "SELECT username FROM user WHERE username = '".$username."' AND password = '".$password."'";
                                     
        if ($result = $conn->query($query)) {
                                  
            while ($data = $result->fetchArray(SQLITE3_ASSOC)) {
                $_SESSION['username'] = $data['username'];
           
                echo "<p>You have been logged in as {$_SESSION['username']}</p><code>";
                include "/flag.txt";
                echo "</code>";

            }
        } else {            
            // falhou o login
            echo "<p>Invalid username or password <a href=\"index.php\">Tente novamente</a></p>";
        }
    }
?>
```

By analyzing the code, we managed to find the SQL query that was executed when an attempt of logging in was made:

```sql
SELECT username FROM user WHERE username = '".$username."' AND password = '".$password."'
```

The fields in the SQL query originate from the user's input, through a POST request. The issue here is that the query is directly concatenating user inputs ```$username``` and ```$password``` into the SQL query string.

This makes the query vulnerable to SQL Injection attacks.

## 3. Finding an Exploit

Having found a vulnerability, we only needed to figure out an exploit that would allow us to access the flag. Since we had no way of knowing what user accounts existed, we needed to come up with a way of *breaking into the vault* without using any specific username.

To do this, we would have to insert SQL code into the username field that would modify the query and list every username from the ```user``` table in the database; therefore, we decided to introduce ```' OR TRUE; #``` into the username field and an arbitrary value (we chose ```enter```) into the password field.

```sql
SELECT username FROM user WHERE username = '' OR TRUE; # AND password = '".$password."'
```

In the query above, ```WHERE username = '' OR TRUE``` creates a condition that is always true, since ```TRUE``` is always considered true in SQL. This means that the query will return all usernames from the ```user``` table because the condition is true for every row - essentially bypassing the username check.
Meanwhile, the ```#``` symbol comments out the ```AND password = '".$password."'``` section of the query, rendering the password check useless. This makes it so that we can insert any value in the password field without having to worry about the query being successful or not.

## 4. Exploring the Vulnerability

Having developed an exploit, we went ahead and inserted the SQL code into the username field and an arbitrary password into the password field, as previously mentioned.

![sql-injection](images/sql-injection-ctf/sql_injection.png)

We were then able to enter the website as an authenticated user and capture the flag.

![flag](images/sql-injection-ctf/flag.png)

***Note:*** After retrieving the flag, and thanks to the ```echo "<p>You have been logged in as {$_SESSION['username']}</p><code>";``` line in PHP, we learned that there was actually a user named ```admin```. Had we known this beforehand, we could have logged into the website by simply inserting ```admin'; #``` into the username field instead of ```' OR TRUE; #``` (just like in Task 2 of the SQL Injection SEED Lab); this would select the user whose username was ```admin```.

![admin-sql-injection](images/sql-injection-ctf/admin_sql_injection.png)