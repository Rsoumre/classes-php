<?php
class Userpdo {
    private $id;
    public $login;
    public $email;
    public $firstname;
    public $lastname;
    private $conn;
    private $isConnected = false;

    // Connexion PDO
    public function __construct() {
        try {
            $this->conn = new PDO("mysql:host=localhost;dbname=classes-php", "admin", "root");
            $this->conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            die("Erreur de connexion : " . $e->getMessage());
        }
    }

    // Inscription avec vérification des doublons
    public function register($login, $password, $email, $firstname, $lastname) {
        // Vérifier si login ou email existe déjà
        $stmt = $this->conn->prepare("SELECT * FROM utilisateurs WHERE login = ? OR email = ?");
        $stmt->execute([$login, $email]);
        if ($stmt->fetch()) {
            return ["error" => "Login ou email déjà utilisé !"];
        }

        // Hash du mot de passe
        $password = password_hash($password, PASSWORD_DEFAULT);

        // Insertion
        $stmt = $this->conn->prepare("INSERT INTO utilisateurs (login, password, email, firstname, lastname) VALUES (?, ?, ?, ?, ?)");
        $stmt->execute([$login, $password, $email, $firstname, $lastname]);

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
        $result = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($result && password_verify($password, $result['password'])) {
            $this->id = $result['id'];
            $this->login = $result['login'];
            $this->email = $result['email'];
            $this->firstname = $result['firstname'];
            $this->lastname = $result['lastname'];
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
    }

    // Supprimer l'utilisateur connecté
    public function delete() {
        if ($this->isConnected) {
            $stmt = $this->conn->prepare("DELETE FROM utilisateurs WHERE id = ?");
            $stmt->execute([$this->id]);
            $this->disconnect();
        }
    }

    // Mise à jour
    public function update($login, $password, $email, $firstname, $lastname) {
        if ($this->isConnected) {
            $password = password_hash($password, PASSWORD_DEFAULT);
            $stmt = $this->conn->prepare("UPDATE utilisateurs SET login=?, password=?, email=?, firstname=?, lastname=? WHERE id=?");
            $stmt->execute([$login, $password, $email, $firstname, $lastname, $this->id]);

            $this->login = $login;
            $this->email = $email;
            $this->firstname = $firstname;
            $this->lastname = $lastname;
        }
    }

    // Vérifie la connexion
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
}
 


// On inclut la classe Userpdo
require_once "user-pdo.php";
 
// Création d'un nouvel objet Userpdo
$user = new Userpdo();

//  Étape 1 : Inscription d'un utilisateur
$result = $user->register("Tom21", "azerty", "tom21@gmail.com", "Tom", "Dupont");
if (isset($result['error'])) {
    echo " " . $result['error'] . "<br>";
} else {
    echo " Utilisateur enregistré avec succès !<br>";
}

//  Étape 2 : Connexion avec le login + mot de passe
if ($user->connect("Tom21", "azerty")) {
    echo " Connexion réussie avec PDO !<br>";
} else {
    echo " Connexion échouée avec PDO !<br>";
}

//  Étape 3 : Afficher toutes les infos de l'utilisateur connecté
echo "<pre>";
print_r($user->getAllInfos());
echo "</pre>";

//  Étape 4 (optionnelle) : Mise à jour des infos
//$user->update("Tom22", "newpass", "tom22@gmail.com", "Thomas", "Dupont");

//  Étape 5 (optionnelle) : Supprimer l'utilisateur
//$user->delete();
