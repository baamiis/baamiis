package main

import (
	"fmt"
	"ksecure"
	"log"
	"os"
)

func main() {

	outputFile, err := os.Create("../firmware/output.bin")
	if err != nil {
		fmt.Println("Error: invalid outputFile")
		return
	}
	defer outputFile.Close()

	inputFile, err := os.Open("../firmware/s_lb_300.bin")
	if err != nil {
		fmt.Println("Error: invalid inputFile")
		return
	}
	defer inputFile.Close()
    /*
	keyFile, err := os.Open("key.key")
	if err != nil {
		// handle error
	}
	defer keyFile.Close()
	*/
	keyFile := "02d20bbd7e394ad5999a4cebabac9619732c343a4cac99470c03e23ba2bdc2bc"
	flashAddress := int(0x210000)
	flashCryptConf := int(0xF)
	doDecrypt := false
	//hash password
    hkey := "6904e03bf4c9e7f53a11f09311e2fa68c750f5de84cd2f63b47defb47d5ef17f"

	err = ksecure.FlashEncryptionOperation(outputFile, inputFile, flashAddress, keyFile, hkey, flashCryptConf, doDecrypt)
	if err != nil {
		log.Print("Encryption operation Failed!!!!\n")
	}
}
