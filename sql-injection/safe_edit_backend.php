<!--
SEED Lab: SQL Injection Education Web plateform
Author: Kailiang Ying
Email: kying@syr.edu
-->
<!--
SEED Lab: SQL Injection Education Web plateform
Enhancement Version 1.
Date: 10th April 2018.
Developer: Kuber Kohli.

Update: The password was stored in the session was updated when password is changed.

Update 2019-02-12: Use prepared statements to protect against SQL injection vulnerabilities.
-->

<!DOCTYPE html>
<html>
<body>

  <?php
  session_start();
  $input_email = $_GET['Email'];
  $input_nickname = $_GET['NickName'];
  $input_address= $_GET['Address'];
  $input_pwd = $_GET['Password'];
  $input_phonenumber = $_GET['PhoneNumber'];
  $uname = $_SESSION['name'];
  $eid = $_SESSION['eid'];
  $id = $_SESSION['id'];

  function getDB() {
    $dbhost="localhost";
    $dbuser="root";
    $dbpass="seedubuntu";
    $dbname="Users";
    // Create a DB connection
    $conn = new mysqli($dbhost, $dbuser, $dbpass, $dbname);
    if ($conn->connect_error) {
      die("Connection failed: " . $conn->connect_error . "\n");
    }
    return $conn;
  }

  $conn = getDB();
  $stmt=null;
  if($input_pwd!=''){
    // In case password field is not empty.
    $hashed_pwd = sha1($input_pwd);
    //Update the password stored in the session.
    $_SESSION['pwd']=$hashed_pwd;
    $stmt = $conn->prepare("UPDATE credential SET nickname = ?, email = ?, address = ?, Password = ?, PhoneNumber = ? WHERE ID = ?;");
    $stmt->bind_param("sssssi", $input_nickname, $input_email, $input_address, $hashed_pwd, $input_phonenumber, $id);
  }else{
    // if passowrd field is empty.
    $stmt = $conn->prepare("UPDATE credential SET nickname = ?, email = ?, address = ?, PhoneNumber = ? WHERE ID = ?;");
    $stmt->bind_param("ssssi", $input_nickname, $input_email, $input_address, $input_phonenumber, $id);
  }
  $stmt->execute();
  $stmt->close();
  $conn->close();
  header("Location: unsafe_home.php");
  exit();
  ?>

</body>
</html>
