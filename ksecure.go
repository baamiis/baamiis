package ksecure

import (
	"bytes"
	ii "crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"strconv"
)

func flashEncryptionTweakRange(flashCryptConfig int) []int {
	tweakRange := make([]int, 0)
	if flashCryptConfig&1 != 0 {
		tweakRange = append(tweakRange, makeRange(67)...)
	}
	if flashCryptConfig&2 != 0 {
		tweakRange = append(tweakRange, makeRange(67, 132)...)
	}
	if flashCryptConfig&4 != 0 {
		tweakRange = append(tweakRange, makeRange(132, 195)...)
	}
	if flashCryptConfig&8 != 0 {
		tweakRange = append(tweakRange, makeRange(195, 256)...)
	}
	return tweakRange
}

func makeRange(n int, args ...int) []int {
	if len(args) == 0 {
		return makeRange(0, n)
	} else if len(args) == 1 {
		return makeRange(n, args[0], 1)
	}
	start, stop, step := n, args[0], args[1]
	if step == 0 {
		panic("step cannot be 0")
	}
	if start < stop && step < 0 {
		step = -step
	}
	if start > stop && step > 0 {
		step = -step
	}
	s := make([]int, 0, (stop-start+step-1)/step)
	for i := start; i != stop; i += step {
		s = append(s, i)
	}
	return s
}

var _FLASH_ENCRYPTION_TWEAK_PATTERN = []int{
	23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
	23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
	23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
	14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
	23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
	23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
	23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
	12, 11, 10, 9, 8, 7, 6, 5,
	23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
	23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
	23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
	10, 9, 8, 7, 6, 5,
	23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
	23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
	23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5,
	8, 7, 6, 5}

func flashEncryptionTweakKey(key []byte, offset int, tweakRange []int) []byte {
	tweakedKey := make([]byte, len(key))
	copy(tweakedKey, key)

	offsetBits := make([]bool, 24)
	for i := 0; i < 24; i++ {
		offsetBits[i] = (offset & (1 << i)) != 0
	}

	for _, bit := range tweakRange {
		if offsetBits[_FLASH_ENCRYPTION_TWEAK_PATTERN[bit]] {
			tweakedKey[bit/8] ^= 1 << (7 - (bit % 8))
		}
	}
	return tweakedKey
}

func loadHardwareKey(keyFile io.Reader) ([]byte, error) {
	key, err := ioutil.ReadAll(keyFile)
	if err != nil {
		return nil, err
	}
	if len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("Key file contains wrong length (%d bytes), 24 or 32 expected.", len(key))
	}
	if len(key) == 24 {
		key = append(key, key[8:16]...)
		log.Println("Using 192-bit key (extended)")
	} else {
		log.Println("Using 256-bit key")
	}
	return key, nil
}

func FlashEncryptionOperation(
	outputFile io.WriteSeeker, 
	inputFile io.ReadSeeker, 
	flashAddress int, 
	keyFile string, 
	hashkey string, 
	flashCryptConf int, 
	doDecrypt bool) error {

	var outputFileBuffer bytes.Buffer

	keyBytes, err := hex.DecodeString(keyFile)
	if err != nil {
		return err
	}

	keyBuffer := bytes.NewBuffer(keyBytes)

	key, err := loadHardwareKey(keyBuffer)
	if err != nil {
		return err
	}

	if flashAddress%16 != 0 {
		return fmt.Errorf("Starting flash address 0x%x must be a multiple of 16", flashAddress)
	}

	if flashCryptConf == 0 {
		fmt.Println("WARNING: Setting FLASH_CRYPT_CONF to zero is not recommended")
	}
	tweakRange := flashEncryptionTweakRange(flashCryptConf)

	var aes cipher.Block
	for {
		pos, err := getInputFilePosition(inputFile)
		if err != nil {
			return err
		}
		blockOffs := flashAddress + int(pos)
		block := make([]byte, 16)
		n, err := inputFile.Read(block)
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if n < 16 {
			if doDecrypt {
				return fmt.Errorf("Data length is not a multiple of 16 bytes")
			}
			pad := 16 - n
			block = append(block, make([]byte, pad)...)
			fmt.Println(fmt.Sprintf("Note: Padding with %d bytes of random data (encrypted data must be multiple of 16 bytes long)", pad))
		}

		if blockOffs%32 == 0 || aes == nil {
			blockKey := flashEncryptionTweakKey(key, blockOffs, tweakRange)
			aes, err = ii.NewCipher(blockKey)
			if err != nil {
				return err
			}
		}

		block = reverse(block)
		if doDecrypt {
			aes.Encrypt(block, block)
		} else {
			aes.Decrypt(block, block)
		}
		block = reverse(block)

		if _, err := outputFileBuffer.Write(block); err != nil {
			return err
		}
	}
	log.Printf("0-outputFile_size=%d\n", outputFileBuffer.Len())
	var final_outputFileBuffer bytes.Buffer
	// Create a new slice of bytes with the size of the buffer
	sizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(sizeBytes, uint32(outputFileBuffer.Len()))

	final_outputFileBuffer.Write(sizeBytes)
	log.Printf("1-outputFile_size=%d\n", final_outputFileBuffer.Len())
	firmware_version := "4.05"
	s, err := strconv.ParseFloat(firmware_version, 32)
	if err != nil {
		return err
	}
	// Create a new slice of bytes with the size of the buffer
	versionBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(versionBytes, uint32(s*100))

	final_outputFileBuffer.Write(sizeBytes)
	log.Printf("2-outputFile_size=%d\n", final_outputFileBuffer.Len())

	final_outputFileBuffer.Write(outputFileBuffer.Bytes())
	log.Printf("3-outputFile_size=%d\n", final_outputFileBuffer.Len())

	// Calculate the HMAC-SHA256 of the buffer
	hkey := []byte(hashkey)
	h := hmac.New(sha256.New, hkey)
	h.Write(outputFileBuffer.Bytes())
	hash := h.Sum(nil)

	// Create a new bytes.Buffer with the hash
	hashBuffer := bytes.NewBuffer(hash)

	// Append the hashBuffer to the end of the buffer
	final_outputFileBuffer.Write(hashBuffer.Bytes())
	log.Printf("4-outputFile_size=%d\n", final_outputFileBuffer.Len())
	outputFile.Write(final_outputFileBuffer.Bytes())
	return nil
}

func getInputFilePosition(inputFile io.ReadSeeker) (int64, error) {
	// Save the current position in the input file
	currentPos, err := inputFile.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}
	// Return the saved position
	return currentPos, nil
}

func getOutpuFilePosition(outpuFile io.WriteSeeker) (int64, error) {
	// Save the current position in the input file
	currentPos, err := outpuFile.Seek(0, io.SeekStart)
	if err != nil {
		return 0, err
	}
	// Return the saved position
	return currentPos, nil
}
func getSize(outpuFile io.WriteSeeker) (int64, error) {

	pos, err := outpuFile.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, err
	}
	_, err = outpuFile.Seek(0, io.SeekStart)
	if err != nil {
		return 0, err
	}

	return pos, nil
}

func reverse(b []byte) []byte {
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}
