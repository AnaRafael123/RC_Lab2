/**
 * download.c - cliente FTP simples (RFC 959) com URLs do tipo RFC 1738
 *
 * Uso:    ./download ftp://[<user>:<password>@]<host>/<url-path>
 * Compilar: gcc -Wall -o download download.c
 *
 * Caso de uso: ligar, autenticar, modo passivo, descarregar UM ficheiro
 * para o diretório atual. Em caso de erro indica a fase em que falhou.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define FTP_PORT 21
#define MAX_STR 1024
#define RESP_SIZE 4096

typedef struct {
    char user[MAX_STR];
    char password[MAX_STR];
    char host[MAX_STR];
    char path[MAX_STR];      /* caminho sem a "/" inicial */
    char filename[MAX_STR];  /* nome do ficheiro (último componente) */
    char ip[16];
} URL;

/* Termina o programa indicando a fase que falhou */
static void fail(const char *phase, const char *resp) {
    fprintf(stderr, "\n[ERRO] Falhou na fase: %s\n", phase);
    if (resp != NULL && resp[0] != '\0')
        fprintf(stderr, "Resposta do servidor:\n%s\n", resp);
    exit(EXIT_FAILURE);
}

/* ---------- 1. Parse do URL ---------- */
int parse_url(const char *arg, URL *url) {
    const char *prefix = "ftp://";
    if (strncmp(arg, prefix, strlen(prefix)) != 0) return -1;

    const char *rest = arg + strlen(prefix);   /* [user:pass@]host/path */
    const char *slash = strchr(rest, '/');
    if (slash == NULL || slash[1] == '\0') return -1;   /* sem caminho */

    /* "authority" = tudo até à primeira '/' */
    char authority[MAX_STR];
    size_t alen = (size_t)(slash - rest);
    if (alen == 0 || alen >= sizeof(authority)) return -1;
    memcpy(authority, rest, alen);
    authority[alen] = '\0';

    /* credenciais por omissão: login anónimo */
    strcpy(url->user, "anonymous");
    strcpy(url->password, "anonymous@");

    char *at = strrchr(authority, '@');
    char *hostpart = authority;
    if (at != NULL) {
        *at = '\0';
        hostpart = at + 1;
        char *colon = strchr(authority, ':');
        if (colon != NULL) {
            *colon = '\0';
            strncpy(url->password, colon + 1, MAX_STR - 1);
            url->password[MAX_STR - 1] = '\0';
        }
        strncpy(url->user, authority, MAX_STR - 1);
        url->user[MAX_STR - 1] = '\0';
    }
    if (hostpart[0] == '\0') return -1;
    strncpy(url->host, hostpart, MAX_STR - 1);
    url->host[MAX_STR - 1] = '\0';

    /* caminho (sem a '/' inicial) e nome do ficheiro */
    strncpy(url->path, slash + 1, MAX_STR - 1);
    url->path[MAX_STR - 1] = '\0';

    const char *last = strrchr(url->path, '/');
    const char *name = (last != NULL) ? last + 1 : url->path;
    if (name[0] == '\0') return -1;   /* URL termina em '/': é um diretório */
    strncpy(url->filename, name, MAX_STR - 1);
    url->filename[MAX_STR - 1] = '\0';

    return 0;
}

/* ---------- 2. DNS ---------- */
int get_ip(const char *host, char *ip) {
    struct hostent *h = gethostbyname(host);
    if (h == NULL) {
        herror("gethostbyname()");
        return -1;
    }
    strncpy(ip, inet_ntoa(*((struct in_addr *) h->h_addr)), 15);
    ip[15] = '\0';
    return 0;
}

/* ---------- 3. Ligação TCP (usada para controlo e dados) ---------- */
int connect_socket(const char *ip, int port) {
    int sockfd;
    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = inet_addr(ip);
    server_addr.sin_port = htons(port);

    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket()");
        return -1;
    }
    if (connect(sockfd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("connect()");
        close(sockfd);
        return -1;
    }
    return sockfd;
}

/* ---------- 4. Enviar comando (acrescenta CRLF) ---------- */
int send_cmd(int sockfd, const char *cmd) {
    char line[MAX_STR + 8];
    int n = snprintf(line, sizeof(line), "%s\r\n", cmd);
    if (n < 0 || (size_t) n >= sizeof(line)) return -1;

    int sent = 0;
    while (sent < n) {
        ssize_t w = write(sockfd, line + sent, n - sent);
        if (w <= 0) {
            perror("write()");
            return -1;
        }
        sent += (int) w;
    }
    return 0;
}

/* ---------- 5. Ler resposta (suporta várias linhas) ----------
 * Linha intermédia: "NNN-texto"; última linha: "NNN texto".
 * Devolve o código (ex.: 220) ou -1 em erro. Guarda o texto em resp. */
int read_response(int sockfd, char *resp, size_t size) {
    size_t total = 0;       /* bytes guardados em resp */
    char line[MAX_STR];
    size_t len = 0;         /* tamanho da linha atual */
    int first_code = -1;
    char c;

    resp[0] = '\0';
    while (1) {
        ssize_t r = read(sockfd, &c, 1);
        if (r < 0) { perror("read()"); return -1; }
        if (r == 0) return -1;          /* servidor fechou a ligação */

        if (len < sizeof(line) - 1) line[len++] = c;
        if (total < size - 1) { resp[total++] = c; resp[total] = '\0'; }

        if (c == '\n') {                /* linha completa */
            line[len] = '\0';
            if (len >= 4 && isdigit((unsigned char) line[0]) &&
                isdigit((unsigned char) line[1]) &&
                isdigit((unsigned char) line[2])) {
                int code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
                if (first_code < 0) first_code = code;
                /* termina na linha "<mesmo código><espaço>" */
                if (code == first_code && line[3] == ' ') {
                    printf("%s", resp);
                    return first_code;
                }
            }
            len = 0;
        }
    }
}

/* Envia comando, lê resposta e verifica o código esperado.
 * Se for 'alt' != 0, também aceita esse código. */
void command(int fd, const char *cmd, int expected, int alt,
             const char *phase, char *resp) {
    printf(">> %s\n", strncmp(cmd, "PASS ", 5) == 0 ? "PASS ****" : cmd);
    if (send_cmd(fd, cmd) < 0) fail(phase, "erro ao enviar comando");
    int code = read_response(fd, resp, RESP_SIZE);
    if (code != expected && (alt == 0 || code != alt)) fail(phase, resp);
}

/* ---------- 6. Parse da resposta ao PASV ----------
 * "227 Entering Passive Mode (h1,h2,h3,h4,p1,p2)" */
int parse_pasv(const char *resp, char *ip, int *port) {
    int h1, h2, h3, h4, p1, p2;
    const char *p = strchr(resp, '(');
    if (p == NULL) return -1;
    if (sscanf(p + 1, "%d,%d,%d,%d,%d,%d", &h1, &h2, &h3, &h4, &p1, &p2) != 6)
        return -1;
    sprintf(ip, "%d.%d.%d.%d", h1, h2, h3, h4);
    *port = p1 * 256 + p2;
    return 0;
}

/* ---------- 7. Receber o ficheiro pela ligação de dados ---------- */
int download_file(int datafd, const char *filename) {
    FILE *f = fopen(filename, "wb");
    if (f == NULL) { perror("fopen()"); return -1; }

    char buf[4096];
    ssize_t n;
    long total = 0;
    while ((n = read(datafd, buf, sizeof(buf))) > 0) {
        if (fwrite(buf, 1, (size_t) n, f) != (size_t) n) {
            perror("fwrite()");
            fclose(f);
            return -1;
        }
        total += n;
    }
    if (n < 0) { perror("read()"); fclose(f); return -1; }

    fclose(f);
    printf("Recebidos %ld bytes -> %s\n", total, filename);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Uso: %s ftp://[<user>:<password>@]<host>/<url-path>\n", argv[0]);
        return EXIT_FAILURE;
    }

    URL url;
    char resp[RESP_SIZE];
    char cmd[MAX_STR + 16];

    /* 1. URL */
    memset(&url, 0, sizeof(url));
    if (parse_url(argv[1], &url) < 0) fail("parse do URL (formato inválido)", NULL);
    printf("User: %s | Host: %s | Caminho: %s | Ficheiro: %s\n",
           url.user, url.host, url.path, url.filename);

    /* 2. DNS */
    if (get_ip(url.host, url.ip) < 0) fail("resolução do nome (DNS)", NULL);
    printf("IP: %s\n", url.ip);

    /* 3. Ligação de controlo + mensagem de boas-vindas (220) */
    int ctrl = connect_socket(url.ip, FTP_PORT);
    if (ctrl < 0) fail("ligação de controlo (porta 21)", NULL);
    if (read_response(ctrl, resp, RESP_SIZE) != 220) fail("mensagem de boas-vindas (esperava 220)", resp);

    /* 4. Autenticação */
    snprintf(cmd, sizeof(cmd), "USER %s", url.user);
    command(ctrl, cmd, 331, 230, "autenticação - USER", resp);
    if (strncmp(resp, "230", 3) != 0) {   /* se já deu 230, não precisa de PASS */
        snprintf(cmd, sizeof(cmd), "PASS %s", url.password);
        command(ctrl, cmd, 230, 0, "autenticação - PASS", resp);
    }

    /* 5. Modo binário */
    command(ctrl, "TYPE I", 200, 0, "modo binário (TYPE I)", resp);

    /* 6. Modo passivo */
    command(ctrl, "PASV", 227, 0, "modo passivo (PASV)", resp);
    char data_ip[16];
    int data_port;
    if (parse_pasv(resp, data_ip, &data_port) < 0) fail("parse da resposta PASV", resp);
    printf("Ligação de dados: %s:%d\n", data_ip, data_port);

    /* 7. Ligação de dados */
    int data = connect_socket(data_ip, data_port);
    if (data < 0) fail("ligação de dados", NULL);

    /* 8. Pedido do ficheiro (150 ou 125 = vai começar a transferência) */
    snprintf(cmd, sizeof(cmd), "RETR %s", url.path);
    command(ctrl, cmd, 150, 125, "pedido do ficheiro (RETR)", resp);

    /* 9. Transferência */
    if (download_file(data, url.filename) < 0) fail("transferência/gravação do ficheiro", NULL);
    close(data);   /* o servidor também fecha; assim sabemos que acabou */

    /* 10. Confirmação final (226) e saída */
    if (read_response(ctrl, resp, RESP_SIZE) != 226) fail("confirmação da transferência (esperava 226)", resp);
    command(ctrl, "QUIT", 221, 0, "terminar sessão (QUIT)", resp);
    close(ctrl);

    printf("\nSUCESSO: ficheiro '%s' guardado no diretório atual.\n", url.filename);
    return EXIT_SUCCESS;
}
