<?php

session_start(); // Démarre la session pour garder la connexion

class Userpdo {
    private $id;
    public $login;
    public $email;
    public $firstname;
    public $lastname;
    private $conn;
    private $isConnected = false;

    // Constructeur : connexion PDO et récupération de l'utilisateur connecté depuis session
    public function __construct() {
        try {
            $this->conn = new PDO("mysql:host=localhost;dbname=classes", "admin", "root");
            $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            die("Erreur de connexion : " . $e->getMessage());
        }

        // Si l'utilisateur est déjà en session, on hydrate l'objet
        if (isset($_SESSION['user_id'])) {
            $this->loadUserById($_SESSION['user_id']);
        }
    }

    // Inscription d'un nouvel utilisateur
    public function register($login, $password, $email, $firstname, $lastname) {
        // Vérification doublon login ou email
        $stmt = $this->conn->prepare("SELECT * FROM utilisateurs WHERE login = ? OR email = ?");
        $stmt->execute([$login, $email]);
        if ($stmt->fetch()) {
            return ["error" => "Login ou email déjà utilisé !"];
        }

        // Hash du mot de passe
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

        // Insertion en base
        $stmt = $this->conn->prepare("INSERT INTO utilisateurs (login, password, email, firstname, lastname) VALUES (?, ?, ?, ?, ?)");
        $stmt->execute([$login, $passwordHash, $email, $firstname, $lastname]);

        return [
            "login" => $login,
            "email" => $email,
            "firstname" => $firstname,
            "lastname" => $lastname
        ];
    }

    // Connexion
    public function connect($login, $password) {
        $stmt = $this->conn->prepare("SELECT * FROM utilisateurs WHERE login = ?");
        $stmt->execute([$login]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            $this->hydrate($user);
            $_SESSION['user_id'] = $this->id; // Sauvegarde la session
            $this->isConnected = true;
            return true;
        }
        return false;
    }

    // Déconnexion
    public function disconnect() {
        $this->id = null;
        $this->login = null;
        $this->email = null;
        $this->firstname = null;
        $this->lastname = null;
        $this->isConnected = false;

        if (isset($_SESSION['user_id'])) {
            unset($_SESSION['user_id']);
        }
    }

    // Supprimer l'utilisateur connecté
    public function delete() {
        if ($this->isConnected) {
            $stmt = $this->conn->prepare("DELETE FROM utilisateurs WHERE id = ?");
            $stmt->execute([$this->id]);
            $this->disconnect();
        }
    }

    // Mettre à jour les infos de l'utilisateur
    public function update($login, $password, $email, $firstname, $lastname) {
        if ($this->isConnected) {
            $passwordHash = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $this->conn->prepare("UPDATE utilisateurs SET login=?, password=?, email=?, firstname=?, lastname=? WHERE id=?");
            $stmt->execute([$login, $passwordHash, $email, $firstname, $lastname, $this->id]);

            // Mettre à jour l'objet
            $this->login = $login;
            $this->email = $email;
            $this->firstname = $firstname;
            $this->lastname = $lastname;
        }
    }

    // Vérifie si l'utilisateur est connecté
    public function isConnected() {
        return $this->isConnected;
    }

    // Retourne toutes les infos
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

    // Getters
    public function getLogin() { return $this->login; }
    public function getEmail() { return $this->email; }
    public function getFirstname() { return $this->firstname; }
    public function getLastname() { return $this->lastname; }

    // ----- Méthodes privées -----

    // Hydrate l'objet avec un tableau issu de la base
    private function hydrate($user) {
        $this->id = $user['id'];
        $this->login = $user['login'];
        $this->email = $user['email'];
        $this->firstname = $user['firstname'];
        $this->lastname = $user['lastname'];
        $this->isConnected = true;
    }

    // Charge un utilisateur par son ID
    private function loadUserById($id) {
        $stmt = $this->conn->prepare("SELECT * FROM utilisateurs WHERE id = ?");
        $stmt->execute([$id]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($user) {
            $this->hydrate($user);
        }
    }
}
