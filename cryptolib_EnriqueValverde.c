#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*COMPILAR: gcc cryptolib_EnriqueValverde.c -lcrypto -ldl
  EJECUTAR: ./a.out
  ARCHIVOS NECESARIOS: words.txt, ciphertext.txt, plaintext.txt
*/

/*Codigo para el metodo do_crypt() obtenido de:
openssl.org/docs/man1.0.2/man3/EVP_EncryptInit.html
modificado ligeramente por Enrique Valverde Soriano

al usar archivos de texto (.txt) es posible que haya que eliminar
el caracter final en el texto plano, el resto de archivos
se crearon usando bless
*/

int do_crypt(FILE *in, FILE *out, int do_encrypt, char *key){

 unsigned char inbuf[32];
 unsigned char outbuf[21];

 int inlen;
 int outlen;
 
 char iv[16] = {0};

 EVP_CIPHER_CTX ctx;
 EVP_CIPHER_CTX_init(&ctx);
 EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, do_encrypt);
 OPENSSL_assert(EVP_CIPHER_CTX_key_length(&ctx) == 16);
 OPENSSL_assert(EVP_CIPHER_CTX_iv_length(&ctx) == 16);
 EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, do_encrypt);

 for(;;) {
  inlen = fread(inbuf, 1, 1024, in);
  if(inlen <= 0) break;
  if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, inlen)) {
   printf("ERROR\n");
   EVP_CIPHER_CTX_cleanup(&ctx);
   return 0;
   } 
  fwrite(outbuf, 1, outlen, out);
  }
 if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen)) {
  EVP_CIPHER_CTX_cleanup(&ctx);
  return 0;
  }
 fwrite(outbuf, 1, outlen, out);

 EVP_CIPHER_CTX_cleanup(&ctx);
 return 1;
}

/* iguales()
comprueba que el contenido de un archivo es identico al de otro
devuelve 0 en caso de que sean identicos
devuelve -1 en caso de que no lo sean
*/

int iguales(FILE *fa, FILE *fb){

 int ch1, ch2;

 ch1 = getc(fa);
 ch2 = getc(fb);

 while ((ch1 != EOF) && (ch2 !=EOF) && (ch1 == ch2)){
  ch1 = getc(fa);
  ch2 = getc(fb);
 }

 if (ch1 == ch2){
  fclose(fa);
  fclose(fb);
  return 0;
 }
 else if (ch1 != ch2){
  fclose(fa);
  fclose(fb);
  return -1;
 }

 return 0;
}

/*main()*/

int main(){

 FILE *fp = fopen("words.txt", "r");
 FILE *plain = fopen("plaintext.txt", "r");

 if(fp == NULL){
  perror("No existe el archivo");
  exit(1);
 }

 unsigned char chunk[16]; //chunk almacena las lineas de texto de words.txt
 int len = 0;

 printf("Buscando clave...\n");
 
 while(fgets(chunk, sizeof(chunk), fp) != NULL){ //bucle de busqueda para la clave (chunk)

  FILE *cipher = fopen("cipher.txt","w+");
  FILE *ctxt = fopen("ciphertext.txt","r+");

  len = strlen(chunk);
  chunk[len-1] = ' '; //eliminamos el caracter "\n" al final de cada palabra leida.
  memset(&chunk[len], ' ',16 - len); //padding con el caracter ' ' para obtener la clave de 16 bytes

  do_crypt(ctxt, cipher, 0, chunk); //llamada al algoritmo de cifrado cipher almacena el resultado, el 0 especifica desencriptar

  fclose(cipher);
  fclose(ctxt);

  FILE *fa = fopen("cipher.txt","r+"); //abrimos el archivo cipher obtenido despues de cifrar
  FILE *fb = fopen("plaintext.txt", "r+"); //abrimos el texto plano nuevamente para poder cerrar el puntero y actualizarlo

  if (iguales(fa, fb) == 0){ //en caso de encontrar un archivo identico al texto plano...
   printf("La clave de cifrado es: ");
   fputs(chunk,stdout);
   printf("\n");
   break;
  }
 }

 fclose(fp);
 fclose(plain);

 return 0;
}

 
