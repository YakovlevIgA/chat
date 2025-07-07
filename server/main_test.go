package main

import (
	"testing"
)

// Мок WebSocket соединения
type mockConn struct {
	sentMessages []string
}

func (m *mockConn) WriteMessage(messageType int, data []byte) error {
	m.sentMessages = append(m.sentMessages, string(data))
	return nil
}

func (m *mockConn) ReadMessage() (int, []byte, error) {
	return 0, nil, nil
}

func (m *mockConn) Close() error {
	return nil
}

func TestSendMessagePrivateAndBroadcast(t *testing.T) {
	room := NewChatRoom()

	aliceConn := &mockConn{}
	bobConn := &mockConn{}

	alice := &Participant{socket: aliceConn, nickname: "alice"}
	bob := &Participant{socket: bobConn, nickname: "bob"}

	room.members[alice] = true
	room.members[bob] = true

	// Тест личного сообщения
	room.sendMessage(alice, "/msg bob Привет, Боб!")

	if len(bobConn.sentMessages) != 1 {
		t.Fatalf("Ожидалось 1 сообщение у Боба, получили %d", len(bobConn.sentMessages))
	}
	if bobConn.sentMessages[0] != "[личное от alice]: Привет, Боб!" {
		t.Errorf("Неверное личное сообщение: %s", bobConn.sentMessages[0])
	}

	// Тест широковещательной рассылки

	aliceConn.sentMessages = nil
	bobConn.sentMessages = nil

	room.sendMessage(alice, "Всем привет!")

	if len(bobConn.sentMessages) != 1 {
		t.Fatalf("Ожидалось 1 сообщение у Боба, получили %d", len(bobConn.sentMessages))
	}
	if bobConn.sentMessages[0] != "alice: Всем привет!" {
		t.Errorf("Неверное широковещательное сообщение: %s", bobConn.sentMessages[0])
	}

	// Отправитель не должен получить сообщение
	if len(aliceConn.sentMessages) != 0 {
		t.Errorf("Отправитель не должен получать сообщение, но получил %d", len(aliceConn.sentMessages))
	}
}
