package main

import (
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"strings"
	"sync"
)

type Socket interface {
	WriteMessage(messageType int, data []byte) error
	ReadMessage() (int, []byte, error)
	Close() error
}

type WSConnWrapper struct {
	*websocket.Conn
}

func (w WSConnWrapper) WriteMessage(messageType int, data []byte) error {
	return w.Conn.WriteMessage(messageType, data)
}

func (w WSConnWrapper) ReadMessage() (int, []byte, error) {
	return w.Conn.ReadMessage()
}

func (w WSConnWrapper) Close() error {
	return w.Conn.Close()
}

var wsUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type Participant struct {
	socket   Socket
	nickname string
}

type User struct {
	password  string
	publicKey string
}

type ChatRoom struct {
	mu      sync.Mutex
	members map[*Participant]bool
	users   map[string]*User
}

func NewChatRoom() *ChatRoom {
	return &ChatRoom{
		members: make(map[*Participant]bool),
		users:   make(map[string]*User),
	}
}

func (cr *ChatRoom) sendMessage(sender *Participant, message string) {
	cr.mu.Lock()
	participants := make([]*Participant, 0, len(cr.members))
	for p := range cr.members {
		participants = append(participants, p)
	}
	cr.mu.Unlock()

	// Обработка личного сообщения
	if strings.HasPrefix(message, "/msg ") {
		parts := strings.SplitN(message, " ", 3)
		if len(parts) < 3 {
			sender.socket.WriteMessage(websocket.TextMessage, []byte("Неверный формат личного сообщения. Используйте /msg имя_пользователя сообщение"))
			return
		}
		targetNick := parts[1]
		privateMsg := parts[2]
		delivered := false

		for _, p := range participants {
			if p.nickname == targetNick {
				p.socket.WriteMessage(websocket.TextMessage, []byte("[личное от "+sender.nickname+"]: "+privateMsg))
				delivered = true
				break
			}
		}
		if !delivered {
			sender.socket.WriteMessage(websocket.TextMessage, []byte("Пользователь "+targetNick+" не найден"))
		}
		return
	}

	// Рассылка
	for _, p := range participants {
		if p != sender {
			p.socket.WriteMessage(websocket.TextMessage, []byte(sender.nickname+": "+message))
		}
	}
}

func (cr *ChatRoom) handleConnection(w http.ResponseWriter, r *http.Request) {
	conn, err := wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Ошибка апгрейда:", err)
		return
	}
	defer conn.Close()

	var participant *Participant

	// Цикл авторизации
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		parts := strings.SplitN(strings.TrimSpace(string(msg)), " ", 4)
		if len(parts) < 4 {
			conn.WriteMessage(websocket.TextMessage, []byte("Неверная команда. Используйте REGISTER nick pass publicKey или LOGIN nick pass publicKey"))
			continue
		}
		cmd := strings.ToUpper(parts[0])
		nick := parts[1]
		pass := parts[2]
		publicKey := parts[3]

		cr.mu.Lock()
		if cmd == "REGISTER" {
			if _, exists := cr.users[nick]; exists {
				conn.WriteMessage(websocket.TextMessage, []byte("Пользователь уже зарегистрирован"))
				cr.mu.Unlock()
				continue
			}
			hashedPass, err := bcrypt.GenerateFromPassword([]byte(pass), bcrypt.DefaultCost)
			if err != nil {
				conn.WriteMessage(websocket.TextMessage, []byte("Ошибка при хешировании пароля"))
				cr.mu.Unlock()
				continue
			}
			cr.users[nick] = &User{
				password:  string(hashedPass),
				publicKey: publicKey,
			}
			conn.WriteMessage(websocket.TextMessage, []byte("Регистрация успешна"))
			cr.mu.Unlock()
			continue
		} else if cmd == "LOGIN" {
			user, ok := cr.users[nick]
			if !ok {
				conn.WriteMessage(websocket.TextMessage, []byte("Неверные ник или пароль"))
				cr.mu.Unlock()
				continue
			}
			if err := bcrypt.CompareHashAndPassword([]byte(user.password), []byte(pass)); err != nil {
				conn.WriteMessage(websocket.TextMessage, []byte("Неверные ник или пароль"))
				cr.mu.Unlock()
				continue
			}

			conn.WriteMessage(websocket.TextMessage, []byte("Вход успешен"))
			participant = &Participant{
				socket:   WSConnWrapper{conn},
				nickname: nick,
			}
			cr.users[nick].publicKey = publicKey
			cr.members[participant] = true

			// Отправляем все публичные ключи клиенту
			var allKeys []string
			for uname, u := range cr.users {
				allKeys = append(allKeys, uname+":"+u.publicKey)
			}
			keysMessage := "PUBLIC_KEYS " + strings.Join(allKeys, ",")
			conn.WriteMessage(websocket.TextMessage, []byte(keysMessage))

			// Рассылаем другим участникам новый публичный ключ
			newKeyMsg := "PUBLIC_KEYS " + nick + ":" + publicKey
			for p := range cr.members {
				if p != participant {
					p.socket.WriteMessage(websocket.TextMessage, []byte(newKeyMsg))
				}
			}

			cr.mu.Unlock()
			break // успешный вход, выходим из цикла авторизации
		} else {
			conn.WriteMessage(websocket.TextMessage, []byte("Неизвестная команда"))
			cr.mu.Unlock()
		}
	}

	log.Printf("Пользователь %s вошёл в чат", participant.nickname)

	// Удаляем участника при выходе
	defer func() {
		cr.mu.Lock()
		delete(cr.members, participant)
		cr.mu.Unlock()
		log.Printf("Пользователь %s покинул чат", participant.nickname)
	}()

	// Цикл чтения сообщений (чат)
	for {
		_, incoming, err := participant.socket.ReadMessage()
		if err != nil {
			log.Println("Ошибка при чтении:", err)
			break
		}

		cr.sendMessage(participant, string(incoming))
	}
}

func main() {
	room := NewChatRoom()
	http.HandleFunc("/ws", room.handleConnection)
	log.Println("Сервер запущен на порту :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
