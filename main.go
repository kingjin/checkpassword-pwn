package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"golang.org/x/exp/mmap"
)

var (
	newline = []byte("\n")
	colon   = []byte(":")
)

func main() {

	fileName := "passwordHash.txt"

	f, err := os.Open(fileName)
	defer f.Close()
	if err != nil {
		fmt.Println(err.Error())
	} else {
		for {
			contentByte := bufio.NewReader(f)
			strLine, _, c := contentByte.ReadLine()

			if c == io.EOF {
				break
			}
			csvLine := strings.Split(string(strLine), ",")
			if len(csvLine) == 4 {
				var checkPwd = csvLine[2]
				checkPwd = strings.ToUpper(checkPwd)
				ChkRes := CheckHashPwd(checkPwd)
				if len(ChkRes) > 0 {
					fmt.Println("命中HASH:", ChkRes)
				}
			}
		}

	}
}
func CheckHashPwd(strPwd string) (res string) {

	// 指定Pwn密码库 此处下载:https://haveibeenpwned.com/Passwords
	filePath := "pwned-passwords-ntlm-ordered-by-hash-v7.txt"
	readerAt, err := mmap.Open(filePath)
	if err != nil {
		fmt.Println(err.Error())
	}

	defer readerAt.Close()

	fi, err := os.Stat(filePath)
	totalLen := fi.Size()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	buff := make([]byte, 128)

	checkPwdBytes := []byte(strPwd)

	var checkRes = ""

	sortTmp := sort.Search(int(totalLen), func(i int) bool {

		readerAt.ReadAt(buff, int64(i))

		line := buff[:]

		if bytes.Index(buff, colon) != hex.EncodedLen(sha1.Size) {
			line = buff[bytes.Index(buff, newline)+1:]
		}
		line = line[:bytes.Index(line, newline)]

		pieces := bytes.Split(line, colon)
		if len(pieces) != 2 {
			return false
		}
		//二分法查找
		var isExist = bytes.Compare(checkPwdBytes, pieces[0])
		if isExist <= 0 {
			checkRes = string(pieces[0])
		}
		return isExist <= 0
	})
	_ = sortTmp

	return checkRes
}
