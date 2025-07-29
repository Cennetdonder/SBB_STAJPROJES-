<?php
// login.php - Giriş işlemi için PHP backend kodu

session_start();
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST');
header('Access-Control-Allow-Headers: Content-Type');

// Veritabanı bağlantısı
require_once 'config/database.php';

class LoginHandler {
    private $db;
    
    public function __construct($database) {
        $this->db = $database;
    }
    
    public function handleLogin() {
        // Sadece POST isteklerini kabul et
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
            $this->sendResponse(false, 'Geçersiz istek metodu');
            return;
        }
        
        try {
            // JSON verilerini al
            $input = json_decode(file_get_contents('php://input'), true);
            
            // POST verileri varsa onları kullan (form submit)
            if (empty($input)) {
                $input = $_POST;
            }
            
            // Giriş verilerini validate et
            $validation = $this->validateInput($input);
            if (!$validation['valid']) {
                $this->sendResponse(false, $validation['message']);
                return;
            }
            
            $email = $validation['email'];
            $password = $validation['password'];
            $rememberMe = $validation['rememberMe'];
            
            // Kullanıcıyı veritabanında ara
            $user = $this->findUser($email);
            
            if (!$user) {
                $this->sendResponse(false, 'E-posta veya şifre hatalı');
                return;
            }
            
            // Şifre kontrolü
            if (!password_verify($password, $user['password'])) {
                // Başarısız giriş denemesini kaydet
                $this->logFailedAttempt($email, $_SERVER['REMOTE_ADDR']);
                $this->sendResponse(false, 'E-posta veya şifre hatalı');
                return;
            }
            
            // Hesap aktif mi kontrol et
            if ($user['status'] !== 'active') {
                $this->sendResponse(false, 'Hesabınız aktif değil. Lütfen yönetici ile iletişime geçin.');
                return;
            }
            
            // Başarılı giriş - session oluştur
            $this->createSession($user, $rememberMe);
            
            // Son giriş zamanını güncelle
            $this->updateLastLogin($user['id']);
            
            // Başarılı giriş logunu kaydet
            $this->logSuccessfulLogin($user['id'], $_SERVER['REMOTE_ADDR']);
            
            // Başarılı yanıt gönder
            $this->sendResponse(true, 'Giriş başarılı', [
                'redirectUrl' => $this->getRedirectUrl($user),
                'user' => [
                    'id' => $user['id'],
                    'name' => $user['first_name'] . ' ' . $user['last_name'],
                    'email' => $user['email'],
                    'role' => $user['role']
                ]
            ]);
            
        } catch (Exception $e) {
            error_log('Login error: ' . $e->getMessage());
            $this->sendResponse(false, 'Sistem hatası oluştu. Lütfen tekrar deneyiniz.');
        }
    }
    
    private function validateInput($input) {
        $result = ['valid' => false, 'message' => ''];
        
        // E-posta kontrolü
        if (empty($input['email'])) {
            $result['message'] = 'E-posta adresi zorunludur';
            return $result;
        }
        
        $email = filter_var(trim($input['email']), FILTER_VALIDATE_EMAIL);
        if (!$email) {
            $result['message'] = 'Geçerli bir e-posta adresi giriniz';
            return $result;
        }
        
        // Kurumsal e-posta kontrolü (isteğe bağlı)
        if (!str_ends_with($email, '@sakarya.bel.tr')) {
            $result['message'] = 'Lütfen kurumsal e-posta adresinizi kullanınız';
            return $result;
        }
        
        // Şifre kontrolü
        if (empty($input['password'])) {
            $result['message'] = 'Şifre zorunludur';
            return $result;
        }
        
        if (strlen($input['password']) < 6) {
            $result['message'] = 'Şifre en az 6 karakter olmalıdır';
            return $result;
        }
        
        $result['valid'] = true;
        $result['email'] = $email;
        $result['password'] = $input['password'];
        $result['rememberMe'] = !empty($input['rememberMe']);
        
        return $result;
    }
    
    private function findUser($email) {
        try {
            $stmt = $this->db->prepare("
                SELECT id, email, password, first_name, last_name, role, status, 
                       created_at, last_login
                FROM users 
                WHERE email = ? AND deleted_at IS NULL
            ");
            
            $stmt->execute([$email]);
            return $stmt->fetch(PDO::FETCH_ASSOC);
            
        } catch (PDOException $e) {
            error_log('Database error in findUser: ' . $e->getMessage());
            throw new Exception('Veritabanı hatası');
        }
    }
    
    private function createSession($user, $rememberMe) {
        // Session verilerini ayarla
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['user_email'] = $user['email'];
        $_SESSION['user_name'] = $user['first_name'] . ' ' . $user['last_name'];
        $_SESSION['user_role'] = $user['role'];
        $_SESSION['login_time'] = time();
        
        // Beni hatırla seçeneği
        if ($rememberMe) {
            // 30 gün boyunca hatırla
            $cookieExpire = time() + (30 * 24 * 60 * 60);
            $token = $this->generateRememberToken($user['id']);
            
            setcookie('remember_token', $token, $cookieExpire, '/', '', true, true);
            
            // Token'ı veritabanına kaydet
            $this->saveRememberToken($user['id'], $token, $cookieExpire);
        }
        
        // Session güvenliği için
        session_regenerate_id(true);
    }
    
    private function generateRememberToken($userId) {
        return hash('sha256', $userId . time() . random_bytes(32));
    }
    
    private function saveRememberToken($userId, $token, $expires) {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO remember_tokens (user_id, token, expires_at) 
                VALUES (?, ?, ?)
                ON DUPLICATE KEY UPDATE 
                token = VALUES(token), expires_at = VALUES(expires_at)
            ");
            
            $stmt->execute([$userId, hash('sha256', $token), date('Y-m-d H:i:s', $expires)]);
            
        } catch (PDOException $e) {
            error_log('Error saving remember token: ' . $e->getMessage());
        }
    }
    
    private function updateLastLogin($userId) {
        try {
            $stmt = $this->db->prepare("
                UPDATE users 
                SET last_login = NOW(), login_count = login_count + 1 
                WHERE id = ?
            ");
            
            $stmt->execute([$userId]);
            
        } catch (PDOException $e) {
            error_log('Error updating last login: ' . $e->getMessage());
        }
    }
    
    private function logSuccessfulLogin($userId, $ipAddress) {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO login_logs (user_id, ip_address, status, created_at) 
                VALUES (?, ?, 'success', NOW())
            ");
            
            $stmt->execute([$userId, $ipAddress]);
            
        } catch (PDOException $e) {
            error_log('Error logging successful login: ' . $e->getMessage());
        }
    }
    
    private function logFailedAttempt($email, $ipAddress) {
        try {
            $stmt = $this->db->prepare("
                INSERT INTO login_logs (email, ip_address, status, created_at) 
                VALUES (?, ?, 'failed', NOW())
            ");
            
            $stmt->execute([$email, $ipAddress]);
            
            // Son 15 dakikada çok fazla başarısız deneme var mı kontrol et
            $this->checkBruteForce($ipAddress);
            
        } catch (PDOException $e) {
            error_log('Error logging failed attempt: ' . $e->getMessage());
        }
    }
    
    private function checkBruteForce($ipAddress) {
        try {
            $stmt = $this->db->prepare("
                SELECT COUNT(*) as attempt_count 
                FROM login_logs 
                WHERE ip_address = ? 
                AND status = 'failed' 
                AND created_at > DATE_SUB(NOW(), INTERVAL 15 MINUTE)
            ");
            
            $stmt->execute([$ipAddress]);
            $result = $stmt->fetch(PDO::FETCH_ASSOC);
            
            // 5'ten fazla başarısız deneme varsa IP'yi geçici olarak engelle
            if ($result['attempt_count'] >= 5) {
                $this->blockIP($ipAddress);
                $