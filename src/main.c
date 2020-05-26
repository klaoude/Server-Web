#include <stdlib.h>
#include <stdio.h>
#include <string.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "httpparser.h"
#include "api.h"
#include "request.h"  

#define ERROR "HTTP/1.0 400 SUCKA\r\n\r\n"
#define MULTIPLE_HEADER "HTTP/1.0 400 Multiple time header\r\n\r\n"
#define REPONSE "HTTP/1.0 200 OK\r\nContent-type: text/plain\r\n\r\n"

#define DEFAULT_FOLDER "www"

#define PORT 8000

char isMultiple(_Token* t)
{
    if(t == NULL)
        return 0;
    return t->next != NULL;
}

char HeaderUnicity(_Token* root)
{
    const int n = 9;
    char* headers[] = {"Transfer_Encoding_header", "Cookie_header", "Referer_header", "User_Agent_header", "Accept_header", "Accept_Encoding_header", "Content_Length_header", "Host_header", "Connection_header"};
    for(int i = 0; i < n; i++)
    {
        _Token* r = searchTree(root, headers[i]);
        if(isMultiple(r))
        {
            purgeElement(&r); 
            printf("Multiple time the header %s\n", headers[i]);
            return 0;
        }
        purgeElement(&r); 
    }
    return 1;
}

char method_conformity(_Token* root)
{
    _Token* r = searchTree(root, "method");
    printf("Method: %.*s\n", ((Lnode*)r->node)->len, ((Lnode*)r->node)->value);
    if(strncmp(((Lnode*)r->node)->value, "GET", 3) == 0)
        return 1;
    if(strncmp(((Lnode*)r->node)->value, "HEAD", 4) == 0)
        return 1;
    if(strncmp(((Lnode*)r->node)->value, "POST", 4) == 0)
    {
        printf("POST request !\n");
        r = searchTree(root, "Content_Length_header");
        if(r == NULL)
        {
            printf("No Content_Length_header !\n");
            return 0;
        }
        char* content_length = malloc(10);
        strncpy(content_length, ((Lnode*)r->node)->value + 16, ((Lnode*)r->node)->len - 16);
        printf("Content_length = %s\n", content_length);

        r = searchTree(root, "message_body");
        if(r == NULL)
        {
            printf("No message_body !\n");
            return 0;
        }
        
        int message_length = strlen(((Lnode*)r->node)->value);
        printf("len mb = %d\n", message_length);
        if(message_length != atoi(content_length))
        {
            printf("content_length != len(message_body) !\n");
            return 0;
        }
    }
    return 1;
}

char HTTPversion_conformity(_Token* root)
{
    _Token* r = searchTree(root, "HTTP_version");
    if(r == NULL)
    {
        printf("No HTTP version !\n");
        return 0;
    }
    
    char* version = calloc(4, 1);
    strncpy(version, ((Lnode*)r->node)->value + 5, 3);
    printf("HTTP version = %s\n", version);
    if(strncmp(version, "0.9", 3) == 0)
        return 1;
    if(strncmp(version, "1.0", 3) == 0)
        return 1;
    if(strncmp(version, "1.1", 3) == 0)
    {
        r = searchTree(root, "Host_header");
        if(r == NULL)
        {
            printf("HTTP version = 1.1 but Host_header not found !\n");
            return 0;
        }
        return 1;
    }
    if(strncmp(version, "2.0", 3) == 0)
        return 1;
    return 0;
}

void urldecode2(char *dst, const char *src)
{
    char a, b;
    while (*src) 
    {
        if ((*src == '%') && ((a = src[1]) && (b = src[2])) && (isxdigit(a) && isxdigit(b))) 
        {
            if (a >= 'a')
                a -= 'a'-'A';
            if (a >= 'A')
                a -= ('A' - 10);
            else
                a -= '0';
            if (b >= 'a')
                b -= 'a'-'A';
            if (b >= 'A')
                b -= ('A' - 10);
            else
                b -= '0';
            *dst++ = 16*a+b;
            src+=3;
        } 
        else if (*src == '+') 
        {
            *dst++ = ' ';
            src++;
        } 
        else
            *dst++ = *src++;
    }
    *dst++ = '\0';
}

void remove_dot_segments(char* dst, const char* src)
{
    while(*src)
    {
        if(strncmp(src, "../", 3) == 0)
            src += 3;
        else if(strncmp(src, "./", 2) == 0)
            src += 3;
        else if(strncmp(src, "/./", 3) == 0)
        {
            *dst = '/';
            src += 3;
        }
        else if(strncmp(src, "/.", 2) == 0)
        {
            *dst = '/';
            src += 3;
        }
        else if(strncmp(src, "/../", 4) == 0)
        {
            *dst = '/';
            src += 4; 
        }
        else if(strncmp(src, "/..", 3) == 0)
        {
            *dst = '/';
            src += 3; 
        }
        else
            *dst++ = *src++;
    }
    *dst++ = '\0';
}

char request_target_treatment(_Token* root, char** path)
{
    _Token* r = searchTree(root, "origin_form");
    if(r == NULL)
        return 0;

    char* url = calloc(((Lnode*)r->node)->len + 1, 1);
    strncpy(url, ((Lnode*)r->node)->value, ((Lnode*)r->node)->len);
    char* urld = calloc(strlen(url) + 1, 1);
    urldecode2(urld, url);
    free(url);
    url = calloc(strlen(urld) + 1, 1);
    remove_dot_segments(url, urld);
    free(urld);
    printf("origin_form = %s\n", url);
    *path = strdup(url);
    free(url);
    return 1;
}

char is_ressource_availible(char* path)
{
    printf("Searching for ressource: %s\n", path);
    FILE* f = fopen(path, "r");
    if(!f)
        return 0;
    fclose(f);
    return 1;
}

//https://gist.github.com/ccbrown/9722406
void DumpHex(const void* data, size_t size) 
{
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

char load_ressource(int cid, _Token* root, char* path)
{
    char* dir = DEFAULT_FOLDER;
    _Token* r = searchTree(root, "Host");
    if(r != NULL)
    {
        char* host = calloc(((Lnode*)r->node)->len + 1, 1);
        strncpy(host, ((Lnode*)r->node)->value, ((Lnode*)r->node)->len);
        printf("Host: %s\n", host);
        if(strcmp(strtok(host, ":"), "localhost") == 0)
            ;
        else if(*host < '0' || *host > '9')
            dir = strtok(host, ".");

        if(strcmp(host, "cazou") == 0)
            dir = DEFAULT_FOLDER;    

        free(host);    

        if(strcmp(path, "/") == 0)
        {
            free(path);
            path = "/index.html";
        }
        
        char* fullpath = malloc(strlen(dir) + strlen(path) + 1);
        strcpy(fullpath, dir);
        strcat(fullpath, path);
        
        if(!is_ressource_availible(fullpath))
        {
            free(fullpath);
            return 0;
        }

        FILE* f = fopen(fullpath, "r");
        fseek(f, 0, SEEK_END);
        int size = ftell(f);
        fseek(f, 0, SEEK_SET);
        char* content = malloc(size);
        fread(content, size, 1, f);
        fclose(f);

        r = searchTree(root, "HTTP_version");
        char* version = calloc(4, 1);
        strncpy(version, ((Lnode*)r->node)->value + 5, 3);
        printf("v = %s\n", version);

        //HTTP/1.1 200 OKrnConnection: rnContent-type: rnContent-Length: rnrn
        int len;
        char* conn;
        if(strcmp(version, "1.0") == 0)
        {
            r = searchTree(root, "Connection_header");
            if(r == NULL)
                conn = "close";
            else      
            {
                conn = calloc(((Lnode*)r->node)->len + 1, 1);             
                strncpy(conn, ((Lnode*)r->node)->value, ((Lnode*)r->node)->len);         
            }
        }
        else
        {
            r = searchTree(root, "Connection_header");
            if(r == NULL)
                conn = "keep-alive";
            else                
            {
                conn = calloc(((Lnode*)r->node)->len + 1, 1);          
                strncpy(conn, ((Lnode*)r->node)->value, ((Lnode*)r->node)->len);         
            }
        }        

        char* cmd = malloc(9 + strlen(fullpath));
        sprintf(cmd, "file -i %s", fullpath);
        FILE* p = popen(cmd, "r");
        char* mime = calloc(255, 1);
        fgets(mime, 254, p);
        mime = strtok(mime, ":;");
        if(mime)
            mime = strtok(NULL, ":;");
        else
            strcpy(mime, "text/plain");

        if(strncmp(fullpath + strlen(fullpath) - 3, "css", 3) == 0)
            strcpy(mime, "text/css");

        printf("MIME = %s\n", mime);
        free(cmd);
        fclose(p);

        char* rep = calloc(51 + size + 7 + strlen(mime) + strlen(conn), 1);
        r = searchTree(root, "method");
        char* method = strdup(getElementValue(r->node, &len));
        sprintf(rep, "HTTP/1.1 200 OK\r\n%s\r\nContent-type:%s\r\nContent-Length: %d\r\n\r\n", conn, mime, size);
        memcpy(rep + strlen(rep), content, size);
        
        printf("\nREPONSE:\n");
        //DumpHex(rep, 51 + size + 7 + strlen(mime) + strlen(conn));
        writeDirectClient(cid, rep, 51 + size + 7 + strlen(mime) + strlen(conn));

        free(method);
        //free(fullpath);
        free(rep);
        //free(mime);
    }
    return 1;
}

void send_error(int cid, int code, char* msg)
{
    char* message = malloc(strlen(msg) + 20);
    sprintf(message, "HTTP/1.0 %d %s\r\n\r\n", code, msg);
    printf("send message: %s\n", message);
    writeDirectClient(cid, message, strlen(message));
}

int main(int argc, char** argv)
{
    printf("Starting server on port %d!\n", PORT);
    message *requete; 
	int res; 

	while (1) 
    {
		if ((requete = getRequest(PORT)) == NULL)
            return -1; 

        puts("------------------------------");
		printf("%.*s\n\n", requete->len, requete->buf);  

        char* conn = NULL;

		if (res = parseur(requete->buf, requete->len)) 
        {
            char error = 0;
			_Token *r,*tok,*root; 

			root = getRootTree(); 

            if(!HeaderUnicity(root))
            {
                send_error(requete->clientId, 400, "BAD REQUEST");
                error = 1;
            }
            if(!method_conformity(root))
            {
                send_error(requete->clientId, 501, "NOT IMPLEMENTED");
                error = 1;
            }
            if(!HTTPversion_conformity(root))
            {
                send_error(requete->clientId, 505, "HTTP VERSION NOT SUPPORTED");
                error = 1;
            }
            char* path;
            if(!request_target_treatment(root, &path))
            {
                send_error(requete->clientId, 505, "HTTP VERSION NOT SUPPORTED");
                error = 1;
            }
            if(!load_ressource(requete->clientId, root, path))
            {
                send_error(requete->clientId, 404, "NOT FOUND");
                error = 1;
            }
            free(path);

            r = searchTree(root, "Connection_header");
            if(strncmp(((Lnode*)r->node)->value, "close", 5) == 0)
                conn = "close";

            purgeTree(root); 
		} 
        else
			writeDirectClient(requete->clientId, ERROR, strlen(ERROR)); 

		endWriteDirectClient(requete->clientId);
        if(conn == NULL) 
		    requestShutdownSocket(requete->clientId); 
	    else if(strcmp(conn, "close") == 0)
            ;
        else
            requestShutdownSocket(requete->clientId); 

        freeRequest(requete);

        puts("------------------------------");
	}

	return 1;
}