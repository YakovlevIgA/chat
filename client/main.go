package main

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

type UserStore struct {
	mu    sync.RWMutex
	users map[string]string
}

func NewUserStore() *UserStore {
	return &UserStore{
		users: make(map[string]string),
	}
}

func (s *UserStore) SetUser(nick, publicKey string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.users[nick] = publicKey
}

func (s *UserStore) GetPublicKey(nick string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.users[nick]
	return key, ok
}

func (s *UserStore) DeleteUser(nick string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, nick)
}

func generateKeyPair(bits int) (privateKeyPEM string, publicKeyPEM string, err error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return "", "", err
	}

	privDER := x509.MarshalPKCS1PrivateKey(privateKey)
	privBlock := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privDER,
	}
	privateKeyPEM = string(pem.EncodeToMemory(&privBlock))

	pubDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", err
	}
	pubBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubDER,
	}
	publicKeyPEM = string(pem.EncodeToMemory(&pubBlock))

	return privateKeyPEM, publicKeyPEM, nil
}

func parsePublicKeys(s string) map[string]string {
	res := make(map[string]string)
	pairs := strings.Split(s, ",")
	for _, pair := range pairs {
		parts := strings.SplitN(pair, ":", 2)
		if len(parts) != 2 {
			continue
		}
		nick := parts[0]
		pubKey := parts[1]
		res[nick] = pubKey
	}
	return res
}

func EncryptWithPublicKey(msg string, pubPEM string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, fmt.Errorf("не удалось декодировать PEM")
	}

	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := pubInterface.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("неверный тип ключа")
	}

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pub, []byte(msg))
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func DecryptWithPrivateKey(ciphertext []byte, privPEM string) (string, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return "", fmt.Errorf("не удалось декодировать PEM")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return "", err
	}

	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

func main() {
	userStore := NewUserStore()

	myPrivateKey, myPublicKey, err := generateKeyPair(2048)
	if err != nil {
		log.Fatal("Ошибка генерации ключей:", err)
	}

	serverAddr := "localhost:8080"
	url := "ws://" + serverAddr + "/ws"

	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		log.Fatal("Не удалось подключиться к серверу:", err)
	}
	defer conn.Close()

	input := bufio.NewReader(os.Stdin)

	// Регистрация или вход
	for {
		fmt.Println("Выберите команду:")
		fmt.Println("1 - Register")
		fmt.Println("2 - Login")
		fmt.Print("Ваш выбор: ")
		choiceRaw, _ := input.ReadString('\n')
		choice := strings.TrimSpace(choiceRaw)

		var command string
		switch choice {
		case "1":
			command = "REGISTER"
		case "2":
			command = "LOGIN"
		default:
			fmt.Println("Неверный выбор")
			continue
		}

		fmt.Print("Введите ник: ")
		nickRaw, _ := input.ReadString('\n')
		nick := strings.TrimSpace(nickRaw)

		fmt.Print("Введите пароль: ")
		passRaw, _ := input.ReadString('\n')
		pass := strings.TrimSpace(passRaw)

		fullCommand := fmt.Sprintf("%s %s %s %s", command, nick, pass, myPublicKey)

		err = conn.WriteMessage(websocket.TextMessage, []byte(fullCommand))
		if err != nil {
			log.Fatal("Ошибка отправки команды:", err)
		}

		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Fatal("Ошибка при чтении ответа:", err)
		}
		fmt.Println(string(msg))

		if strings.HasPrefix(string(msg), "Регистрация успешна") ||
			strings.HasPrefix(string(msg), "Неверные ник или пароль") ||
			strings.HasPrefix(string(msg), "Неизвестная команда") {
			continue
		}
		if strings.HasPrefix(string(msg), "Вход успешен") {
			break
		}
	}

	// Чтение сообщений от сервера
	go func() {
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				log.Println("Ошибка при чтении:", err)
				os.Exit(0)
			}
			textMsg := string(msg)

			// Обновление публичных ключей
			if strings.HasPrefix(textMsg, "PUBLIC_KEYS ") {
				keysStr := strings.TrimPrefix(textMsg, "PUBLIC_KEYS ")
				keysMap := parsePublicKeys(keysStr)

				for nick, pubKey := range keysMap {
					userStore.SetUser(nick, pubKey)
				}

				fmt.Println("Обновлены публичные ключи пользователей")
				continue
			}

			// Расшифровка личных сообщений
			if strings.HasPrefix(textMsg, "[личное от ") {
				parts := strings.SplitN(textMsg, "]: ", 2)
				if len(parts) == 2 {
					sender := strings.TrimPrefix(parts[0], "[личное от ")
					encodedMsg := parts[1]

					ciphertext, err := base64.StdEncoding.DecodeString(encodedMsg)
					if err != nil {
						fmt.Println("Ошибка декодирования сообщения:", err)
						continue
					}
					plaintext, err := DecryptWithPrivateKey(ciphertext, myPrivateKey)
					if err != nil {
						fmt.Println("Ошибка дешифровки:", err)
						continue
					}
					fmt.Printf("[личное от %s]: %s\n", sender, plaintext)
					continue
				}
			}

			fmt.Println(textMsg)
		}
	}()

	// Отправка сообщений (с шифрованием личных)
	for {
		fmt.Print("> ")
		textRaw, err := input.ReadString('\n')
		if err != nil {
			break
		}
		text := strings.TrimSpace(textRaw)
		if text == "" {
			continue
		}
		if text == "/quit" {
			break
		}

		if strings.HasPrefix(text, "/msg ") {
			parts := strings.SplitN(text, " ", 3)
			if len(parts) < 3 {
				fmt.Println("Неверный формат личного сообщения. Используйте /msg ник сообщение")
				continue
			}
			targetNick := parts[1]
			plainMsg := parts[2]

			pubKey, ok := userStore.GetPublicKey(targetNick)
			if !ok {
				fmt.Println("Публичный ключ пользователя не найден")
				continue
			}

			encryptedBytes, err := EncryptWithPublicKey(plainMsg, pubKey)
			if err != nil {
				fmt.Println("Ошибка шифрования:", err)
				continue
			}

			encodedMsg := base64.StdEncoding.EncodeToString(encryptedBytes)
			encryptedText := fmt.Sprintf("/msg %s %s", targetNick, encodedMsg)

			err = conn.WriteMessage(websocket.TextMessage, []byte(encryptedText))
			if err != nil {
				log.Println("Ошибка отправки сообщения:", err)
				break
			}
		} else {
			err = conn.WriteMessage(websocket.TextMessage, []byte(text))
			if err != nil {
				log.Println("Ошибка отправки сообщения:", err)
				break
			}
		}
	}
}
