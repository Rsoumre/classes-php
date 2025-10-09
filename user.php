<?php
// Définition d'une classe User pour gérer les utilisateurs (inscription, connexion, suppression, etc.)
class User {

    private $id;              
    public $login;            
    public $email;             
    public $firstname;        
    public $lastname;         
    private $isConnected = false;          
    

    // Cette méthode est automatiquement appelée lors de la création d'un nouvel objet User.
    // Elle établit la connexion à la base de données.
    public function __construct() {
        $this->conn = new mysqli("localhost", "admin", "root", "classes-php");
        // Si la connexion échoue, on arrête le script avec un message d'erreur.
        if ($this->conn->connect_error) {
            die("Erreur de connexion : " . $this->conn->connect_error);
        }
    }

    // === Inscription d'un utilisateur ===
    public function register($login, $password, $email, $firstname, $lastname) {
        // Vérifie si le login OU l'email existe déjà dans la base
        $stmt = $this->conn->prepare("SELECT * FROM utilisateurs WHERE login = ? OR email = ?");
        $stmt->bind_param("ss", $login, $email);
        $stmt->execute();
        $result = $stmt->get_result();

        // Si un résultat existe déjà, on renvoie un message d'erreur
        if ($result->num_rows > 0) {
            return ["error" => "Login ou email déjà utilisé !"];
        }

        // Sinon, on chiffre le mot de passe pour plus de sécurité
        $password = password_hash($password, PASSWORD_DEFAULT);

        // On insère le nouvel utilisateur dans la table `utilisateurs`
        $stmt = $this->conn->prepare("INSERT INTO utilisateurs (login, password, email, firstname, lastname) VALUES (?, ?, ?, ?, ?)");
        $stmt->bind_param("sssss", $login, $password, $email, $firstname, $lastname);
        $stmt->execute();

        // On retourne les infos du nouvel utilisateur sous forme de tableau
        return [
            "login" => $login,
            "email" => $email,
            "firstname" => $firstname,
            "lastname" => $lastname
        ];
    }

    // === Connexion d'un utilisateur ===
    public function connect($login, $password) {
        // On récupère l'utilisateur correspondant au login donné
        $stmt = $this->conn->prepare("SELECT * FROM utilisateurs WHERE login = ?");
        $stmt->bind_param("s", $login);
        $stmt->execute();
        $result = $stmt->get_result()->fetch_assoc();

        // Si le login existe et que le mot de passe correspond (vérification du hash)
        if ($result && password_verify($password, $result['password'])) {
            // On "hydrate" l'objet avec les infos de l'utilisateur connecté
            $this->id = $result['id'];
            $this->login = $result['login'];
            $this->email = $result['email'];
            $this->firstname = $result['firstname'];
            $this->lastname = $result['lastname'];
            $this->isConnected = true;
            return true; // connexion réussie
        }
        return false; // échec de connexion
    }

    // === Déconnexion ===
    public function disconnect() {
        // On réinitialise toutes les données de l'objet
        $this->id = null;
        $this->login = null;
        $this->email = null;
        $this->firstname = null;
        $this->lastname = null;
        $this->isConnected = false;
    }

    // === Suppression d'un utilisateur connecté ===
    public function delete() {
        // On ne supprime que si l'utilisateur est connecté
        if ($this->isConnected) {
            $stmt = $this->conn->prepare("DELETE FROM utilisateurs WHERE id = ?");
            $stmt->bind_param("i", $this->id);
            $stmt->execute();
            // Après suppression, on déconnecte l'utilisateur
            $this->disconnect();
        }
    }

    // === Mise à jour des informations de l'utilisateur ===
    public function update($login, $password, $email, $firstname, $lastname) {
        if ($this->isConnected) {
            // On chiffre le nouveau mot de passe
            $password = password_hash($password, PASSWORD_DEFAULT);
            // On met à jour les informations dans la base
            $stmt = $this->conn->prepare("UPDATE utilisateurs SET login=?, password=?, email=?, firstname=?, lastname=? WHERE id=?");
            $stmt->bind_param("sssssi", $login, $password, $email, $firstname, $lastname, $this->id);
            $stmt->execute();

            // On met aussi à jour les attributs de l'objet
            $this->login = $login;
            $this->email = $email;
            $this->firstname = $firstname;
            $this->lastname = $lastname;
        }
    }

    // === Vérifie si un utilisateur est connecté ===
    public function isConnected() {
        return $this->isConnected;
    }

    // === Retourne toutes les infos de l'utilisateur connecté ===
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

    // === Getters ===
    // Ces fonctions permettent d'accéder à certaines informations
    public function getLogin() { return $this->login; }
    public function getEmail() { return $this->email; }
    public function getFirstname() { return $this->firstname; }
    public function getLastname() { return $this->lastname; }
}



// Création d'un nouvel objet utilisateur
$user = new User();

// Étape 1 : Inscription d'un utilisateur
$result = $user->register("Tom20", "azerty", "tom20@gmail.com", "Tom", "Dupont");

// Si l'inscription échoue (login ou email déjà pris), on affiche une erreur
if (isset($result['error'])) {
    echo " " . $result['error'] . "<br>";
} else {
    echo " Utilisateur enregistré avec succès !<br>";
}

// Étape 2 : Connexion de l'utilisateur
if ($user->connect("Tom20", "azerty")) {
    echo " Connexion réussie !<br>";
} else {
    echo " Connexion échouée !<br>";
}

// Étape 3 : Affichage de toutes les informations de l'utilisateur connecté
echo "<pre>";
print_r($user->getAllInfos());
echo "</pre>";

// Étape 4 : Mise à jour des infos (optionnelle)
//$user->update("Tom21", "newpass", "tom21@gmail.com", "Thomas", "Dupont");

// Étape 5 : Suppression de l'utilisateur (optionnelle)
//$user->delete();
