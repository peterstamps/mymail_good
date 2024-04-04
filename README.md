# mymail_good
A good SMTP based mail program using OPENSSL and STARTTLS protocol. Tested on standard SMTP servers of KPN and GMAIL

Install development libraries e.g. sudo apt-get install build-essential openssl libcrypto 
// check and adapt lines 47 - 55 --> your email credentials, sender en receiver adresses and the SMTP server settings are required
// compile g++ -o mymail mymail_good.cpp -lssl -lcrypto
// run ./mymail
