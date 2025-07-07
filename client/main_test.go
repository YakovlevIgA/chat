package main

import (
	"testing"
)

// Тест генерации ключей и проверки корректности
func TestGenerateKeyPair(t *testing.T) {
	priv, pub, err := generateKeyPair(2048)
	if err != nil {
		t.Fatalf("Ошибка генерации ключей: %v", err)
	}
	if priv == "" || pub == "" {
		t.Fatal("Сгенерированные ключи не должны быть пустыми")
	}
}

// Тест шифрования и дешифрования
func TestEncryptDecrypt(t *testing.T) {
	priv, pub, err := generateKeyPair(2048)
	if err != nil {
		t.Fatalf("Ошибка генерации ключей: %v", err)
	}

	originalMsg := "test message"
	ciphertext, err := EncryptWithPublicKey(originalMsg, pub)
	if err != nil {
		t.Fatalf("Ошибка шифрования: %v", err)
	}

	plaintext, err := DecryptWithPrivateKey(ciphertext, priv)
	if err != nil {
		t.Fatalf("Ошибка дешифровки: %v", err)
	}

	if plaintext != originalMsg {
		t.Fatalf("Дешифрованное сообщение не совпадает. Ожидали: %q, получили: %q", originalMsg, plaintext)
	}
}

// Тест EncryptWithPublicKey с неверным публичным ключом
func TestEncryptWithInvalidPublicKey(t *testing.T) {
	_, err := EncryptWithPublicKey("message", "invalid-pem")
	if err == nil {
		t.Fatal("Ожидали ошибку при шифровании с неверным публичным ключом")
	}
}

// Тест DecryptWithPrivateKey с неверным приватным ключом
func TestDecryptWithInvalidPrivateKey(t *testing.T) {
	ciphertext := []byte("testdata")
	_, err := DecryptWithPrivateKey(ciphertext, "invalid-pem")
	if err == nil {
		t.Fatal("Ожидали ошибку при дешифровке с неверным приватным ключом")
	}
}

// Тест DecryptWithPrivateKey с неподходящим шифротекстом
func TestDecryptInvalidCiphertext(t *testing.T) {
	priv, _, err := generateKeyPair(2048)
	if err != nil {
		t.Fatalf("Ошибка генерации ключей: %v", err)
	}

	ciphertext := []byte("invalid-ciphertext")
	_, err = DecryptWithPrivateKey(ciphertext, priv)
	if err == nil {
		t.Fatal("Ожидали ошибку при дешифровке неверного ciphertext")
	}
}

// Тест парсинга строки с публичными ключами
func TestParsePublicKeys(t *testing.T) {
	input := "alice:key1,bob:key2,charlie:key3"
	keys := parsePublicKeys(input)
	if len(keys) != 3 {
		t.Fatalf("Ожидали 3 ключа, получили %d", len(keys))
	}
	if keys["alice"] != "key1" {
		t.Errorf("alice: ожидается 'key1', получили '%s'", keys["alice"])
	}
	if keys["bob"] != "key2" {
		t.Errorf("bob: ожидается 'key2', получили '%s'", keys["bob"])
	}
	if keys["charlie"] != "key3" {
		t.Errorf("charlie: ожидается 'key3', получили '%s'", keys["charlie"])
	}
}

// Тест parsePublicKeys с пустой строкой
func TestParsePublicKeysEmpty(t *testing.T) {
	keys := parsePublicKeys("")
	if len(keys) != 0 {
		t.Errorf("Ожидали пустую карту, получили %d элементов", len(keys))
	}
}

// Тест parsePublicKeys с некорректной парой без двоеточия
func TestParsePublicKeysInvalidPair(t *testing.T) {
	input := "alice:key1,invalidpair,bob:key2"
	keys := parsePublicKeys(input)
	if len(keys) != 2 {
		t.Errorf("Ожидали 2 ключа, получили %d", len(keys))
	}
	if _, ok := keys["invalidpair"]; ok {
		t.Error("Неожиданно нашли invalidpair как валидную пару")
	}
}

// Тест UserStore: SetUser, GetPublicKey, DeleteUser
func TestUserStore(t *testing.T) {
	store := NewUserStore()

	store.SetUser("user1", "pubkey1")
	store.SetUser("user2", "pubkey2")

	if key, ok := store.GetPublicKey("user1"); !ok || key != "pubkey1" {
		t.Errorf("Ожидали 'pubkey1' для user1, получили '%s', ok=%v", key, ok)
	}
	if key, ok := store.GetPublicKey("user2"); !ok || key != "pubkey2" {
		t.Errorf("Ожидали 'pubkey2' для user2, получили '%s', ok=%v", key, ok)
	}

	store.DeleteUser("user1")
	if _, ok := store.GetPublicKey("user1"); ok {
		t.Error("Ожидали, что user1 удалён, но он всё ещё есть")
	}
}

// Тест UserStore: перезапись существующего пользователя
func TestUserStoreOverwrite(t *testing.T) {
	store := NewUserStore()
	store.SetUser("user", "key1")
	store.SetUser("user", "key2")

	if key, _ := store.GetPublicKey("user"); key != "key2" {
		t.Errorf("Ожидали 'key2' после перезаписи, получили '%s'", key)
	}
}
