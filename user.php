<?php
session_start(); 

class User {

    private ?int $id = null;
    public $login;
    public $email;
    public $firstname;
    public $lastname;
    private $isConnected = false;
    private $conn;

    public function __construct() {
        $this->conn = new mysqli("localhost", "admin", "root", "classes-php");
        if ($this->conn->connect_error) {
            die("Erreur de connexion : " . $this->conn->connect_error);
        }

        //  Si l’utilisateur est déjà en session, on restaure sa connexion
        if (isset($_SESSION['user_id'])) {
            $this->loadUserFromSession();
        }
    }

    private function loadUserFromSession() {
        $stmt = $this->conn->prepare("SELECT * FROM utilisateurs WHERE id = ?");
        $stmt->bind_param("i", $_SESSION['user_id']);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();

        if ($user) {
            $this->id = $user['id'];
            $this->login = $user['login'];
            $this->email = $user['email'];
            $this->firstname = $user['firstname'];
            $this->lastname = $user['lastname'];
            $this->isConnected = true;
        }
    }

    // === Inscription ===
    public function register($login, $password, $email, $firstname, $lastname) {
        $stmt = $this->conn->prepare("SELECT * FROM utilisateurs WHERE login = ? OR email = ?");
        $stmt->bind_param("ss", $login, $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            return ["error" => "Login ou email déjà utilisé !"];
        }

        $password = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $this->conn->prepare("INSERT INTO utilisateurs (login, password, email, firstname, lastname) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("sssss", $login, $password, $email, $firstname, $lastname);
        $stmt->execute();

        return [
            "login" => $login,
            "email" => $email,
            "firstname" => $firstname,
            "lastname" => $lastname
        ];
    }

    // === Connexion ===
    public function connect($login, $password) {
        $stmt = $this->conn->prepare("SELECT * FROM utilisateurs WHERE login = ?");
        $stmt->bind_param("s", $login);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();

        if ($result && password_verify($password, $result['password'])) {
            $this->id = $result['id'];
            $this->login = $result['login'];
            $this->email = $result['email'];
            $this->firstname = $result['firstname'];
            $this->lastname = $result['lastname'];
            $this->isConnected = true;

            //  On garde la connexion active dans la session
            $_SESSION['user_id'] = $this->id;
            return true;
        }
        return false;
    }

    // === Déconnexion ===
    public function disconnect() {
        $this->id = null;
        $this->login = null;
        $this->email = null;
        $this->firstname = null;
        $this->lastname = null;
        $this->isConnected = false;
        session_destroy(); // Vide la session
    }

    // === Suppression ===
    public function delete() {
        if ($this->id) { //  on supprime même si page rechargée
            $stmt = $this->conn->prepare("DELETE FROM utilisateurs WHERE id = ?");
            $stmt->bind_param("i", $this->id);
            $stmt->execute();
            $this->disconnect();
        }
    }

    // === Autres méthodes ===
    public function update($login, $password, $email, $firstname, $lastname) {
        if ($this->isConnected) {
            $password = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $this->conn->prepare("UPDATE utilisateurs SET login=?, password=?, email=?, firstname=?, lastname=? WHERE id=?");
            $stmt->bind_param("sssssi", $login, $password, $email, $firstname, $lastname, $this->id);
            $stmt->execute();

            $this->login = $login;
            $this->email = $email;
            $this->firstname = $firstname;
            $this->lastname = $lastname;
        }
    }

    public function isConnected() { return $this->isConnected; }

    public function getAllInfos() {
        if ($this->isConnected) {
            return [
                "id" => $this->id,
                "login" => $this->login,
                "email" => $this->email,
                "firstname" => $this->firstname,
                "lastname" => $this->lastname
            ];
        }
        return null;
    }
}
