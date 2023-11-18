# LOGBOOK 8

This lab's objective was to learn more about SQL Injection attacks on web applications. 
SQL injection is a code injection technique that exploits the vulnerabilities in the interface between web
applications and database servers. The vulnerability is present when user’s inputs are not correctly checked
within the web applications before being sent to the back-end database servers.

## Environment Setup

We used a web application, which was a simple employee management application.
There were two containers in the Lab setup: one for hosting the web application, and the other for hosting the
database for the web application. The IP address for the web application container was ```10.9.0.5```, and the
URL for the web application was http://www.seed-server.com.

Therefore, we needed to map this hostname to the container’s IP address, by adding the entry ```10.9.0.5 www.seed-server.com``` to the */etc/hosts* file.
After this, we set up the Lab's environment using the *docker-compose.yml* file present in the *Labsetup* folder by running the ```dcup``` command (an alias for ```docker-compose up```).

## Task 1: Get Familiar with SQL Statements

The objective of this task was to get familiar with SQL commands by playing with the provided database - in this specific case, a MySQL database hosted on our MySQL container.

The database we were using was called *sqllab_users*, which contained a table called *credential*. This table
stored the personal information (like the employee ID, password, salary, ssn...) of every employee.

Our first goal was to get a shell on the MySQL container.

To do this, we checked the provided Docker manual, which told us we had to run the ```docker ps``` command and then look for the container's specific ID.
Therefore, we ran the following commands to get a shell on the MySQL container:

- ```dockps``` (an alias of ```docker ps```) to get the IDs of the containers
- ```docksh <container-id>``` to open a shell on the MySQL container

![shell-in-mysql](images/logbook-8/shell_in_container.png)

Our second goal was to use the ```mysql``` client program to interact with the database - the username is
```root``` and password is ```dees```.

After logging in, we loaded the existing database (since the *sqllab_users* database had already been created for us) using the ```use``` command. To check the tables present in the *sqllab_users* database, we ran the ```show tables``` command, which printed out all the tables of the selected database.

![login-and-load](images/logbook-8/login_and_load.png)

![tables](images/logbook-8/tables.png)

We then used a SQL query to print all the profile information of the employee Alice.

![alice-info](images/logbook-8/alice_info.png)

## Task 2: SQL Injection Attack on SELECT Statement

SQL injection basically consists in executing your own malicious SQL statements ("malicious payload"). Through these malicious SQL statements, attackers can steal information from the targeted database or even make changes to the database itself.

For this task, we used the login page from http://www.seed-server.com for this task; our goal, as an attacker, was to log into the web application without knowing any employee’s credentials.

![login-page](images/logbook-8/seed_login_page.png)

To get started, we checked out the login page's PHP code in *Labsetup/image_www/Code/unsafe_home.php*. The code snippet below showcases how users are authenticated.

```php
$input_uname = $_GET[’username’];
$input_pwd = $_GET[’Password’];
$hashed_pwd = sha1($input_pwd);
...
$sql = "SELECT id, name, eid, salary, birth, ssn, address, email,
    nickname, Password
    FROM credential
    WHERE name= ’$input_uname’ and Password=’$hashed_pwd’";
$result = $conn->query($sql);
```

The vulnerable SQL statement used two variables ```input_uname``` and ```hashed_pwd```, where ```input_uname``` held the string typed by users in the username field of the login page and ```hashed_pwd``` held the sha1 hash of the password typed by the user. 

The program checked whether any record matched with the provided username and password; if there were a match, the user would be successfully authenticated and would be given the corresponding employee information; otherwise, the authentication would fail.

### Task 2.1: SQL Injection Attack from webpage

Our task was to log into the web application as the administrator (whose account name was ```admin```) from the login page, so we could access the information of all the employees.

To access the admin's account, we basically needed a ```SELECT name, password FROM credential WHERE name = 'admin' AND...``` statement. The problem here was that we didn't know the administrator's password; therefore, we focused our attack on the username field.

We attempted to insert ```admin'; #``` into the username field - this would select the user from the ```credential``` table whose username was ```admin```. At the same time, ```;``` closed the statement/query and ```#``` commented out the password field. For this reason, we inserted an arbitrary password - in this case, ```enter``` - and were given access to the admin page.

![admin-login-attempt](images/logbook-8/admin_login_attempt.png)

![admin-success](images/logbook-8/admin_success.png)

### Task 2.2: SQL Injection Attack from command line

This time around, our goal was to repeat Task 2.1, but without using the webpage. The SEED Lab suggested using the ```curl``` command to send am HTTP GET request to the web application.

It also suggests encoding special characters in a way they can be sent in the request and not change its meaning; therefore, we used ```%20``` for white spaces and ```%27``` for single quotes. Additionally, we discovered that we had to use ```%23``` to encode the hashtag.

![curl-command](images/logbook-8/curl_command.png)

By running this command, we got access to the HTML code of the admin's page.

![curl-info-exposed](images/logbook-8/curl_html_exposed.png)

### Task 2.3: Append a new SQL statement

In this subtask, we attempted to run two SQL statements via the login page. We decided to remove the hashtag that was commenting out the rest of the statement and introduce an ```UPDATE``` statement to set Alice's salary to 1.

Therefore, we introduced ```admin'; UPDATE credential SET salary = 1 WHERE name = 'Alice'; #``` in the username field.

![double-statement](images/logbook-8/double_statement.png)

However, when submitting the payload, we got an error.

![double-statement-error](images/logbook-8/double_statement_error.png)

Thanks to the SEED book/MySQL manual, we got a tip on what was causing this error, so we decided to inspect the PHP snippet that showed how users authenticated in the web application.

```php
$result = $conn->query($sql);
```

The countermeasure mentioned in the SEED Lab is the ```mysqli::query``` function, which only allows for one query to be performed on the database.
For our payload to be successful, we would have to replace the previously mentioned function with ```mysqli::multi_query```, which allows one or more queries on the database.

```php
$result = $conn->multi_query($sql);
```

## Task 3: SQL Injection Attack on UPDATE Statement

There was also a page that allowed employees to update their profile information, including their nickname, email, address, phone number, and password. To go to this page, employees needed to log in first. 
When employees updated their information through this page, a SQL ```UPDATE``` query would be executed. The PHP code implemented in the *unsafe_edit_backend.php* file was used to update the employee’s profile information.

```php
$hashed_pwd = sha1($input_pwd);
$sql = "UPDATE credential SET
    nickname=’$input_nickname’,
    email=’$input_email’,
    address=’$input_address’,
    Password=’$hashed_pwd’,
    PhoneNumber=’$input_phonenumber’
    WHERE ID=$id;";
$conn->query($sql);
```

![edit-profile-page](images/logbook-8/edit_profile_page.png)

### Task 3.1: Modify your own salary

Assuming that we were Alice, our goal was to increase our own salary by exploiting the SQL injection vulnerability in the *Edit Profile* page.

Therefore, we logged in using Alice's account in order to access her *Edit Profile* page.

![alice-profile](images/logbook-8/alice_profile.png)

We then employed a strategy similar to the one we utilized in Task 2.1: by adding the ```', salary = '40000``` statement to the *NickName* field, we made it so that the ```UPDATE``` statement updated the user's salary as well, by basically adding the ```salary``` column to the query.

![alice-increasing-salary](images/logbook-8/alice_increasing_salary.png)

We were then able to verify that our request was successful and that the salary was indeed updated.

![alice-post-edit-salary](images/logbook-8/alice_new_salary.png)

### Task 3.2: Modify other people’s salary

In this subtask, our goal was to punish Alice's boss, Boby, by reducing his salary to 1 dollar.

Since this time we had to change someone else's salary, we had to "delete" ```WHERE ID=$id;``` from the ```UPDATE``` statement. In order to achieve this, we modified the statement we utilized in the previous task .

The new statement, ```', salary = '1' WHERE Name = 'Boby'; #``` is placed in the *Phone Number* field to allow the hashtag to "comment out" the user ID check.

![boby-reducing-salary](images/logbook-8/boby_reducing_salary.png)

By accessing Boby's profile, we were able to verify that we had successfully updated his salary from Alicia's *Edit Profile* page.

![boby-updated-profile](images/logbook-8/boby_updated_profile.png)

### Task 3.3: Modify other people’s password

Changing Boby's salary wasn't enough, so we then had to also change his password. One detail mentioned by the SEED Lab is that the database stores the hash value of passwords instead of the plaintext password string.

Therefore, apart from hashing the new password - which was ```YouShallNotPass``` - the only changed we had to perform on the Task 3.2 statement was replacing ```salary``` with ```password```.

The new password's SHA-1 hash was ```6ae04bd0bc52b3ef88a94b03bdceb179c7facabd```, so the statement to be inserted in the *Phone Number* field would be ```', password = '6ae04bd0bc52b3ef88a94b03bdceb179c7facabd' WHERE Name = 'Boby'; #```.

![boby-updating-password](images/logbook-8/boby_updating_password.png)

We then managed to successfully access Boby's account using his new credentials.

![boby-new-password](images/logbook-8/boby_new_password.png)

![boby-password-profile](images/logbook-8/boby_password_profile.png)