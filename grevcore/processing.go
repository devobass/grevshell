package grevcore

import (
	"io"
	"encoding/binary"
	"log/slog"
)

func ReceivePacket(r io.Reader, key []byte) []byte {
	recvSize := make([]byte, 4)	

	io.ReadFull(r, recvSize)
	size := binary.LittleEndian.Uint32(recvSize)

	if size > MaxPacketSize {
		slog.Error("Packet too large.")
		return nil
	}

	received := make([]byte, size)

	_, err := io.ReadFull(r, received)

	if err != nil {
		slog.Error("An error occured while reading the sent packet.", slog.Any("ERROR", err))
		return nil
	}

	if len(received) == 0 {
		return nil
	}

	return AesDecrypt(received, key)
}

func SendPacket(w io.Writer, data, key []byte) {
	sendSize := make([]byte, 4)		

	encryptedData := AesEncrypt(data, key)
	binary.LittleEndian.PutUint32(sendSize, uint32(len(encryptedData)))

	w.Write(sendSize)
	w.Write(encryptedData)
}
