package util

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

var HEX_RUNES = []rune{
	'0',
	'1',
	'2',
	'3',
	'4',
	'5',
	'6',
	'7',
	'8',
	'9',
	'a',
	'b',
	'c',
	'd',
	'e',
	'f',
}

func CheckIfSliceContains[T comparable](slice []T, ele T) bool {

	hit := false

	for i := 0; i < len(slice); i++ {

		if slice[i] == ele {

			hit = true

			return hit
		}

	}

	return hit

}

func PopFromSliceByIndex[T comparable](slice []T, idx int) (T, []T) {

	pop_val := slice[idx]

	return pop_val, append(slice[:idx], slice[idx+1:]...)

}

func InsertToSliceByIndex[T comparable](slice []T, idx int, val T) []T {

	return append(slice[:idx], append([]T{val}, slice[idx:]...)...)
}

func SplitStrict(content string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		if len(key) == 0 || key[0] == '#' {
			continue
		}

		value := parts[1]
		if len(value) > 2 && value[0] == '"' && value[len(value)-1] == '"' {

			var err error
			value, err = strconv.Unquote(value)
			if err != nil {
				continue
			}
		}
		out[key] = value
	}
	return out
}

func MakeOSReleaseLinux() map[string]string {

	var osRelease map[string]string

	if osRelease == nil {

		osRelease = map[string]string{}
		if bytes, err := os.ReadFile("/etc/os-release"); err == nil {
			osRelease = SplitStrict(string(bytes))
		}
	}
	return osRelease
}

func SliceContains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}

func RandomHex(n int) (string, error) {
	bytes := make([]byte, n)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

type ShellConnection struct {
	*ssh.Client
	password string
}

func ShellConnect(addr, user, password string) (*ShellConnection, error) {

	var hostkeyCallback = ssh.InsecureIgnoreHostKey()

	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		HostKeyCallback: hostkeyCallback,
	}

	conn, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		return nil, err
	}

	return &ShellConnection{conn, password}, nil

}

func (conn *ShellConnection) SendCommands(cmds string) ([]byte, error) {
	session, err := conn.NewSession()
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	err = session.RequestPty("xterm", 80, 40, modes)
	if err != nil {
		return []byte{}, err
	}

	stdoutB := new(bytes.Buffer)
	session.Stdout = stdoutB
	in, _ := session.StdinPipe()

	go func(in io.Writer, output *bytes.Buffer) {

		t_start := time.Now()

		for {

			t_now := time.Now()

			diff := t_now.Sub(t_start)
			if strings.Contains(string(output.Bytes()), "[sudo] password for ") {
				_, err = in.Write([]byte(conn.password + "\n"))
				if err != nil {
					break
				}
				break
			}
			if diff.Seconds() > 30 {
				break
			}
		}
	}(in, stdoutB)

	err = session.Run(cmds)
	if err != nil {
		return []byte{}, err
	}
	return stdoutB.Bytes(), nil
}

func (conn *ShellConnection) SendCommandsBackground(cmds string) ([]byte, error) {
	session, err := conn.NewSession()
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()

	stdoutB := new(bytes.Buffer)
	session.Stdout = stdoutB
	in, _ := session.StdinPipe()

	go func(in io.Writer, output *bytes.Buffer) {

		t_start := time.Now()

		for {

			t_now := time.Now()

			diff := t_now.Sub(t_start)

			if strings.Contains(string(output.Bytes()), "[sudo] password for ") {
				_, err = in.Write([]byte(conn.password + "\n"))
				if err != nil {
					break
				}
				break
			}

			if diff.Seconds() > 30 {
				break
			}

		}
	}(in, stdoutB)

	err = session.Start(cmds)
	if err != nil {
		return []byte{}, err
	}
	return stdoutB.Bytes(), nil
}

func SanitizeUnnecessary(line string) string {

	ret := ""

	line = strings.ReplaceAll(line, " ", "")
	line = strings.ReplaceAll(line, "\n", "")

	llen := len(line)

	for i := 0; i < llen; i++ {

		if line[i] == '[' || line[i] == ']' {

			continue

		} else if line[i] == ',' {

			ret += " "

		} else {

			ret += string(line[i])

		}

	}

	return ret
}
