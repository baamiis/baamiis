### Hi there š


**baamiis/baamiis** is a āØ _special_ āØ repository because its `README.md` (this file) appears on your GitHub profile.

Here are some ideas to get you started:

- š­ Iām currently working on converting esptool from python to Go
- š± Iām currently learning Go and Rust
- šÆ Iām looking to collaborate on converting the esptool to golang
- š¤ Iām looking for help with converting the esptool to golang
- š¬ Ask me about anything (from Embedded to backend)
- š« How to reach me: baamiis7@gmail.com
- š Pronouns: baamiis7
- ā” Fun fact: peace and hapiness = love


**ESP32 Encryption and decryption tool written using GoLang**
Yes, it is possible to convert C code to Go (also known as Golang). There are a few different approaches you can take to do this:
Manually translate the code: This involves going through the C code and writing the equivalent Go code line by line. This can be time-consuming, but it is a good way to learn Go and understand how the code is working.

**Why I needed GoLang version**
I know there is an esptool written by espressif which was written in python. I needed to encrypt the binary image for ota and used the esptool on our server. our server uses c and Golang so to use the esptool we had to spawn a esptool python process to do the encryption then go and read the resulting image. This was very slow and not efficient way of doing things Hence I decided to re-write it in Golang.

Enjoy!! and please let us know if you find any errors or you are interested to help converting all the esptool to GoLang.

