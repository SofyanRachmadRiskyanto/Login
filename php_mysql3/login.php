<?php
    session_start();

    //periksa apakah user sudah login. jika sudah, maka langsung redirect / pindah otomatis ke halaman index.php
    if(isset($_SESSION["loggedin"]) && $_SESSION["loggedin"] === true){
        header("location: index.php");
        exit;
    }

//include koneksi data
    require_once "connect.php";

//definisi variabel dan beri nilai kosong dulu
    $username = $password = "";
    $username_err = $password_err = $login_err = "";

//pemrosesan data ketika form login di-submit
    if($_SERVER['REQUEST_METHOD'] == 'POST'){
    //validasi isian form
    //1. Periksa apakah username kosong
    if(empty(trim($_POST["username"]))){
        $username_err = "Please enter a username";
    } else {
        $username = trim($_POST["username"]);
    }

    //3. Periksa apakah password kosong
    if(empty(trim($_POST["username"]))){
        $password_err = "Please enter a password";
    }else{
        $password = trim($_POST["password"]);
    }

    //validasi login
    if(empty($username_err) && empty($password_err)){
        //query select untuk menyeleksi satu data
        $sql = "SELECT id username, password FROM users WHERE username = ?";

        if($stmt = $conn->prepare($sql)){
            //pembuatan statement dari query sql
            $stmt->bind_param("s", $param_username);
            $param_username = $username;

            //eksekusi statement
            if($stmt->execute()){
                $stmt->store_result();

                //periksa apakah username yg diinputkan ada/terdafter. Jika ya, maka verifikasi apakah passwordnya sesuai
                if($stmt->num_rows == 1){
                    //ikat hasilnya ke dalam statement
                    $stmt->bind_result($id, $username, $hashed_password, $level);
                    if($stmt->fetch()){
                        if(password_verify($password, $hashed_password)){ //jika password yang diisikan pengguna cocok dengan password yang ada di database (hashed password)
                           //maka buat session baru

                           //login sebagai admin
                           if ($level == "admin"){
                               session_start();
                               $_SESSION["loggedin"] = true;
                               $_SESSION["id"] = $id;
                               $_SESSION["level"] = $level;

                               //redirect ke halaman admin
                               header("location: index.php");
                        } else {
                            session_start();
                            $_SESSION["loggedin"] = true;
                            $_SESSION["id"] = $id;
                            $_SESSION["level"] = $level;
                            //redirect ke halaman pembeli
                            header("location: homepage.php");
                           }
                            session_start();
                            $_SESSION["loggedin"] = true;
                            $_SESSION["id"] = $id;
                            $_SESSION["username"] = $username;
                            $_SESSION["level"] = $level;

                            //auto pindah ke halaman index.php setelah login
                            header("location:index.php");
                        } else {
                            session_start();
                            $_SESSION["loggedin"] = true;
                            $_SESSION["id"] = $id;
                            $_SESSION["username"] = $username;
                            $_SESSION["level"] = $level;

                            
                            //password tidak valid, tampilkan pesan error
                            $login_err = "invalid username or password";
                        }
                    }
                }else{
                    $login_err = "Username doesn't exist";
                }

            }else{
                echo "Oops! Something went wrong. Please try again later";
            }

            //close statement
            $stmt->close();
        }
    }
    //close koneksi database
    $conn->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link rel="stylesheet" href="css/bootstrap.min.css">
    <link rel="stylesheet" href="css/login.css">
    <title>LOGIN</title>
</head>
<body>
    <section class="vh-100 gradient-custom">
        <div class="card">
        <?php
            if(!empty($login_err)){
                echo '<div class= "alert alert-danger">' . $login_err . '</div>';
            }
            ?>
            <div class="card-title">
                <h2>LOGIN</h2>
                <div class="underline-text"></div>
            </div>
            <form method="POST" class="form">
                <label for="username">
                    &nbsp;Username
                </label>
                <input id="username" class="form-content" type="username" name="username" required />
                <label for="password" style="margin-top:4%;">
                    &nbsp;Password
                </label>
                <input id="password" class="form-content" type="password" name="password" required />
                <a href=""><legend class="forgot-pass">Forgot Password?</legend></a>
                <input class="submit-btn" type="submit" name="submit" value="LOGIN">
                <a href="register.php" class="sign-up">Don't have account yet? <span style="color:red">Sign Up</span><a>
            </form>
        </div> 
    </section>
</body>
</html>