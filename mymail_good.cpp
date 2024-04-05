// check and adapt lines 47 - 55 
// compile g++ -o mymail mymail_good.cpp -lssl -lcrypto
// run ./mymail
#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <sstream>
#include <netdb.h>

const int BUFFER_SIZE = 5120;

std::string base64_encode(const std::string &input) {
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;
    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_write(bio, input.c_str(), input.length());
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

std::string buildAttachment(const std::string &filename, const std::string &data) {
    std::stringstream attachment;
    attachment << "--boundary\r\n";
    attachment << "Content-Type: image/jpeg\r\n";
    attachment << "Content-Disposition: attachment; filename=\"" << filename << "\"\r\n";
    attachment << "Content-Transfer-Encoding: base64\r\n\r\n";
    attachment << base64_encode(data) << "\r\n";
    return attachment.str();
}

int main() {
    // SMTP server configuration
    const char* smtpServer = "your.smtp.server";
    const int smtpPort = 587;
    const char* username = "your.emailAccount@example.com";
    const char* password = "your.AccountPassword";
    const char* senderEmail = "sender.email@example.com";
    const char* recipientEmail = "receiver.email@example.com";
    const char* subject = "Email from my system";
    const char* body = "This is an email with an attached JPG file.";
    const char* attachment_file = "./test.jpg";

    std::cout << "***  Get SMTP server IP address" << std::endl;
    // Get SMTP server IP address
    struct hostent *server = gethostbyname(smtpServer);
    if (server == NULL) {
        std::cerr << "Error: Failed to resolve SMTP server hostname." << std::endl;
        return 1;
    }
    char* smtpServerIP = inet_ntoa(*((struct in_addr*) server->h_addr));

    std::cout << "***  Initialize OpenSSL" << std::endl;
    // Initialize OpenSSL
    SSL_library_init();
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());

    std::cout << "***  Create socket" << std::endl;
    // Create socket
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (clientSocket == -1) {
        std::cerr << "Error: Failed to create socket." << std::endl;
        return 1;
    }

    std::cout << "***  Connect to SMTP server without SSL" << std::endl;
    // Connect to SMTP server without SSL
    struct sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(smtpPort); // SMTP port
    serverAddress.sin_addr.s_addr = inet_addr(smtpServerIP);
    
    if (connect(clientSocket, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) == -1) {
        std::cerr << "Error: Connection to SMTP server failed." << std::endl;
        close(clientSocket);
        return 1;
    }

    std::cout << "***  Receive initial response from server" << std::endl;
    // Receive initial response from server
    char buffer[BUFFER_SIZE];
    recv(clientSocket, buffer, BUFFER_SIZE, 0);
    std::cout << buffer << std::endl;

    std::cout << "***  Send EHLO command" << std::endl;
    // Send EHLO command
    std::string ehloCommand = "EHLO client\r\n";
    send(clientSocket, ehloCommand.c_str(), ehloCommand.size(), 0);
    recv(clientSocket, buffer, BUFFER_SIZE, 0);
    std::cout << buffer << std::endl;

    std::cout << "***  Send STARTTLS command" << std::endl;
    // Send STARTTLS command
    std::string starttlsCommand = "STARTTLS\r\n";
    send(clientSocket, starttlsCommand.c_str(), starttlsCommand.size(), 0);
    recv(clientSocket, buffer, BUFFER_SIZE, 0);
    std::cout << buffer << std::endl;

    std::cout << "***  Start SSL/TLS" << std::endl;
    // Start SSL/TLS
    SSL *ssl = SSL_new(ssl_ctx);
    SSL_set_fd(ssl, clientSocket);
    if (SSL_connect(ssl) == -1) {
        std::cerr << "Error: SSL connection failed." << std::endl;
        SSL_free(ssl);
        close(clientSocket);
        return 1;
    }
    
    std::cout << "***  Send EHLO command over SSL" << std::endl;
    // Send EHLO command over SSL
    std::string ehloCommandSSL = "EHLO client\r\n";
    SSL_write(ssl, ehloCommandSSL.c_str(), ehloCommandSSL.size());
    SSL_read(ssl, buffer, BUFFER_SIZE);
    //std::cout << buffer << std::endl;

    std::cout << "***  Send AUTH LOGIN command" << std::endl;
    // Send AUTH LOGIN command
    std::string authLoginCommand = "AUTH LOGIN\r\n";
    SSL_write(ssl, authLoginCommand.c_str(), authLoginCommand.size());
    SSL_read(ssl, buffer, BUFFER_SIZE);
    //std::cout << buffer << std::endl;

    std::cout << "***  Send base64 encoded username" << std::endl;
    // Send base64 encoded username
    std::string usernameBase64 = base64_encode(username);
    SSL_write(ssl, (usernameBase64 + "\r\n").c_str(), usernameBase64.size() + 2);
    SSL_read(ssl, buffer, BUFFER_SIZE);
    //std::cout << buffer << std::endl;

    std::cout << "***  Send base64 encoded password" << std::endl;
    // Send base64 encoded password
    std::string passwordBase64 = base64_encode(password);
    SSL_write(ssl, (passwordBase64 + "\r\n").c_str(), passwordBase64.size() + 2);
    SSL_read(ssl, buffer, BUFFER_SIZE);
    //std::cout << buffer << std::endl;

    std::cout << "***  Send MAIL FROM command" << std::endl;
    // Send MAIL FROM command
    std::string mailFromCommand = "MAIL FROM: <" + std::string(senderEmail) + ">\r\n";
    SSL_write(ssl, mailFromCommand.c_str(), mailFromCommand.size());
    SSL_read(ssl, buffer, BUFFER_SIZE);
    //std::cout << buffer << std::endl;

    std::cout << "***  Send RCPT TO command" << std::endl;
    // Send RCPT TO command
    std::string rcptToCommand = "RCPT TO: <" + std::string(recipientEmail) + ">\r\n";
    SSL_write(ssl, rcptToCommand.c_str(), rcptToCommand.size());
    SSL_read(ssl, buffer, BUFFER_SIZE);
    //std::cout << buffer << std::endl;

    std::cout << "***  Send DATA command" << std::endl;
    // Send DATA command
    std::string dataCommand = "DATA\r\n";
    SSL_write(ssl, dataCommand.c_str(), dataCommand.size());
    SSL_read(ssl, buffer, BUFFER_SIZE);
    //std::cout << buffer << std::endl;

    std::cout << "***  Send email headers and body" << std::endl;
    // Send email headers and body
    std::string emailData = "From: " + std::string(senderEmail) + "\r\n";
    emailData += "To: " + std::string(recipientEmail) + "\r\n";
    emailData += "Subject: " + std::string(subject) + "\r\n";
    emailData += "Content-Type: multipart/mixed; boundary=boundary\r\n\r\n";
    emailData += "--boundary\r\n";
    emailData += "Content-Type: text/plain\r\n\r\n";
    emailData += std::string(body) + "\r\n";
 
    std::cout << "***  Read attachment file and append attachment to email data" << std::endl;
    // Read attachment file and append attachment to email data
    std::ifstream file(attachment_file, std::ios::binary);
    if (file) {
        std::string attachment((std::istreambuf_iterator<char>(file)), (std::istreambuf_iterator<char>()));
        emailData += buildAttachment("image.jpg", attachment);
        file.close();
    } else {
        std::cerr << "Error: Failed to open JPG file." << std::endl;
        SSL_free(ssl);
        close(clientSocket);
        return 1;
    }
     
    std::cout << "***  End MIME boundary" << std::endl;
    // End MIME boundary
    emailData += "--boundary--\r\n";

    std::cout << "***  End of DATA" << std::endl;
    // End of DATA
    emailData += "\r\n.\r\n";

    std::cout << "***  Send email data" << std::endl;
    // Send email data
    SSL_write(ssl, emailData.c_str(), emailData.size());
    SSL_read(ssl, buffer, BUFFER_SIZE);
    //std::cout << buffer << std::endl;

    std::cout << "***  Send QUIT command" << std::endl;
    // Send QUIT command
    std::string quitCommand = "QUIT\r\n";
    SSL_write(ssl, quitCommand.c_str(), quitCommand.size());
    SSL_read(ssl, buffer, BUFFER_SIZE);
    //std::cout << buffer << std::endl;

    std::cout << "***  Close SSL connection and free SSL context" << std::endl;
    // Close SSL connection and free SSL context
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ssl_ctx);

    std::cout << "***  Close socket" << std::endl;
    // Close socket
    close(clientSocket);

    std::cout << "***  End of program" << std::endl;
    return 0;
}
